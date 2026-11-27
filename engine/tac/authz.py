"""TACACS+ style authorization primitives.

Every authorization decision binds together the requesting user, the
requested service and the exact command (including each positional
argument).  Anything that is not explicitly allowed is denied.
"""

import hashlib
import hmac
import json
import time

WILDCARD = "*"
DEFAULT_SESSION_TTL = 300

# Fields covered by the request signature, in canonicalization terms.
SIGNED_FIELDS = ("session", "seq", "user", "service", "cmd", "args")

# Canonical order of failure reason codes in batch results.
REASON_CODES = ("signature", "session", "user", "service", "command")


def parse_request(raw):
    """Normalize a JSON object or mapping into a request dictionary.

    The returned mapping always contains exactly the seven contract fields;
    ``args`` and ``signature`` default to empty values.
    """
    data = _as_mapping(raw)

    args = data.get("args")
    if args is None:
        args = []
    elif isinstance(args, str):
        args = [args]
    else:
        args = list(args)

    seq = data.get("seq", 0)
    if seq is None:
        seq = 0

    signature = data.get("signature", "")
    if signature is None:
        signature = ""

    return {
        "session": data.get("session"),
        "seq": int(seq),
        "user": data.get("user"),
        "service": data.get("service"),
        "cmd": data.get("cmd"),
        "args": args,
        "signature": signature,
    }


def _as_mapping(raw):
    """Accept a mapping or JSON text/bytes and return a plain mapping."""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8")
    if isinstance(raw, str):
        data = json.loads(raw)
    elif isinstance(raw, dict):
        return dict(raw)
    else:
        raise TypeError("request must be a mapping or JSON text")
    if not isinstance(data, dict):
        raise TypeError("request must be a JSON object")
    return data


def _match(value, pattern):
    """Exact string match; the wildcard pattern matches any string value."""
    if not isinstance(value, str) or not isinstance(pattern, str):
        return False
    return pattern == WILDCARD or value == pattern


def check_session(store, session, seq, now):
    """Validate that a session sequence has not been used before.

    The first use of a sequence number is recorded and returns True.
    Replaying a recorded sequence in the same live session returns False.
    Once the session has passed its ``expires`` time it is re-established
    with a fresh seen-set, so sequence numbers may start over.
    """
    if not isinstance(session, str) or not session:
        return False
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        return False

    if now is None:
        now = time.time()

    if not isinstance(store, dict):
        return False
    sessions = store.get("sessions")
    if not isinstance(sessions, dict):
        sessions = {}
        store["sessions"] = sessions

    entry = sessions.get(session)
    if not isinstance(entry, dict):
        entry = None

    # Expired or malformed entries are replaced with a fresh session.
    if entry is not None:
        expires = entry.get("expires", 0)
        try:
            expired = expires is None or now >= expires
        except TypeError:
            expired = True
        if expired:
            entry = None

    if entry is None:
        entry = {"seen": set(), "expires": now + DEFAULT_SESSION_TTL}
        sessions[session] = entry

    seen = entry.get("seen")
    if not isinstance(seen, set):
        if isinstance(seen, (list, tuple, frozenset)):
            seen = set(seen)
        else:
            seen = set()
        entry["seen"] = seen

    if seq in seen:
        return False

    seen.add(seq)
    return True


def check_user(user, policy):
    """Return True when the user is authorized by the policy.

    Deny entries always win over allow entries; anything not explicitly
    allowed is rejected.
    """
    policy = policy or {}
    users = policy.get("users") or {}
    allow = users.get("allow") or []
    deny = users.get("deny") or []
    if any(_match(user, pattern) for pattern in deny):
        return False
    return any(_match(user, pattern) for pattern in allow)


def check_service(service, policy):
    """Return True when the service is authorized by the policy.

    Unknown services (not matched by an allow entry) are rejected, and
    explicit deny entries take precedence over wildcard allows.
    """
    policy = policy or {}
    services = policy.get("services") or {}
    allow = services.get("allow") or []
    deny = services.get("deny") or []
    if any(_match(service, pattern) for pattern in deny):
        return False
    return any(_match(service, pattern) for pattern in allow)


def check_command(cmd, args, policy):
    """Return True only when an allow rule matches command and every argument.

    Command names match exactly (or via a standalone wildcard).  Rule
    arguments must be the same length as the request arguments and match
    position by position, with a wildcard matching one argument at that
    position.  Only rules with ``allow`` exactly True can grant access.
    """
    if not isinstance(cmd, str) or not cmd:
        return False
    if not isinstance(args, (list, tuple)):
        return False
    args = list(args)

    policy = policy or {}
    for rule in policy.get("commands") or []:
        if not isinstance(rule, dict):
            continue
        # Only explicitly positive rules grant authorization.
        if rule.get("allow") is not True:
            continue

        if not _match(cmd, rule.get("cmd", WILDCARD)):
            continue

        rule_args = rule.get("args")
        if rule_args is None:
            rule_args = []
        elif isinstance(rule_args, str):
            rule_args = [rule_args]
        else:
            try:
                rule_args = list(rule_args)
            except TypeError:
                continue

        # Argument count must agree exactly...
        if len(rule_args) != len(args):
            continue

        # ...and every position must match.
        if all(_match(value, pattern) for value, pattern in zip(args, rule_args)):
            return True

    return False


def verify_signature(request, key):
    """Return True when the request carries a valid HMAC-SHA256 signature.

    The six signed fields are canonicalized with sorted keys and compact
    JSON separators.  Any change to a signed field, a missing signature or
    a wrong key makes verification fail.
    """
    if not isinstance(request, dict):
        return False
    if not key:
        return False

    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        key_bytes = bytes(key)
    else:
        return False

    signature = request.get("signature")
    if not isinstance(signature, str) or len(signature) != 64:
        return False
    try:
        int(signature, 16)
    except ValueError:
        return False

    try:
        body = {name: request.get(name) for name in SIGNED_FIELDS}
        blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        expected = hmac.new(key_bytes, blob, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    except (TypeError, ValueError):
        return False


def validate_policy(policy):
    """Return a list of problem codes found in an authorization policy.

    Possible codes are ``missing_command_rules``, ``overbroad_wildcard``
    and ``missing_signature``.  A healthy policy returns an empty list.
    """
    policy = policy or {}
    issues = []

    commands = policy.get("commands")
    if not isinstance(commands, (list, tuple)) or len(commands) == 0:
        issues.append("missing_command_rules")
    else:
        for rule in commands:
            if not isinstance(rule, dict):
                continue
            # Only a rule that actually grants can be overbroad.
            if rule.get("allow") is not True:
                continue
            if rule.get("cmd") != WILDCARD:
                continue

            rule_args = rule.get("args")
            if rule_args is None:
                issues.append("overbroad_wildcard")
                break
            if isinstance(rule_args, str):
                arg_patterns = [rule_args]
            else:
                try:
                    arg_patterns = list(rule_args)
                except TypeError:
                    continue
            if arg_patterns == [WILDCARD]:
                issues.append("overbroad_wildcard")
                break

    if not policy.get("require_signature"):
        issues.append("missing_signature")

    return issues


def authz_batch(requests, store, key):
    """Authorize each request independently and collect per-request results.

    Every request is checked for signature, session sequence replay, user,
    service and command.  The session check records fresh sequence numbers
    in ``store``; one request's outcome never changes another request's
    identity or input.
    """
    if not isinstance(store, dict):
        store = {}
    policy = store.get("policy") or {}

    results = []
    for raw in requests or []:
        try:
            data = _as_mapping(raw)
            request = parse_request(data)
        except (TypeError, ValueError, UnicodeDecodeError):
            results.append(
                {
                    "session": None,
                    "seq": None,
                    "allowed": False,
                    "reasons": ["signature"],
                }
            )
            continue

        now = data.get("now")
        if now is None:
            now = time.time()

        # Gates are ordered exactly like the documented reason codes.  A
        # request is allowed only when every gate passes; the first failing
        # gate names the reason.  Signature is verified before touching the
        # replay table so an unauthenticated caller cannot burn sequences.
        reasons = []
        if not verify_signature(request, key):
            reasons.append("signature")
        elif not check_session(store, request["session"], request["seq"], now):
            reasons.append("session")
        elif not check_user(request["user"], policy):
            reasons.append("user")
        elif not check_service(request["service"], policy):
            reasons.append("service")
        elif not check_command(request["cmd"], request["args"], policy):
            reasons.append("command")

        results.append(
            {
                "session": request["session"],
                "seq": request["seq"],
                "allowed": not reasons,
                "reasons": reasons,
            }
        )

    return {"results": results, "allowed": all(item["allowed"] for item in results)}
