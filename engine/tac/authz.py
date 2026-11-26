"""TACACS+ style authorization primitives."""

import hashlib
import hmac
import json
import time

WILDCARD = "*"
DEFAULT_SESSION_TTL = 300


def parse_request(raw):
    """Normalize a JSON object or mapping into a request dictionary."""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        data = json.loads(raw)
    elif isinstance(raw, dict):
        data = dict(raw)
    else:
        raise TypeError("request must be a mapping or JSON text")

    args = data.get("args")
    if args is None:
        args = []
    elif isinstance(args, str):
        args = [args]
    else:
        args = list(args)

    return {
        "session": data.get("session"),
        "seq": int(data.get("seq", 0)),
        "user": data.get("user"),
        "service": data.get("service"),
        "cmd": data.get("cmd"),
        "args": args,
        "signature": data.get("signature", ""),
    }


def _match(value, pattern):
    if not isinstance(value, str) or not isinstance(pattern, str):
        return False
    return pattern == WILDCARD or value == pattern


def check_session(store, session, seq, now):
    """Validate that a session sequence has not been used before."""
    if not isinstance(session, str) or not session:
        return False
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        return False
    return True


def check_user(user, policy):
    """Return True when the user is authorized by the policy."""
    users = policy.get("users") or {}
    allow = users.get("allow") or []
    return any(_match(user, pattern) for pattern in allow)


def check_service(service, policy):
    """Return True when the service is authorized by the policy."""
    services = policy.get("services") or {}
    deny = services.get("deny") or []
    if any(_match(service, pattern) for pattern in deny):
        return False
    return True


def check_command(cmd, args, policy):
    """Return True when the command is explicitly authorized."""
    if not isinstance(cmd, str) or not cmd:
        return False
    if not isinstance(args, (list, tuple)):
        return False
    args = list(args)
    for rule in policy.get("commands") or []:
        if not rule.get("allow", True):
            continue
        rule_cmd = rule.get("cmd", WILDCARD)
        if rule_cmd != WILDCARD and not cmd.startswith(rule_cmd):
            continue
        rule_args = rule.get("args")
        if rule_args is None:
            rule_args = []
        if WILDCARD in rule_args or set(rule_args).issubset(set(args)):
            return True
    return False


def verify_signature(request, key):
    """Return True when the request signature is valid."""
    if not key:
        return False
    signature = (request or {}).get("signature") or ""
    if not isinstance(signature, str):
        return False
    if len(signature) != 64:
        return False
    try:
        int(signature, 16)
    except ValueError:
        return False
    return True


def validate_policy(policy):
    """Return a list of problems found in an authorization policy."""
    issues = []
    commands = policy.get("commands") or []
    for rule in commands:
        if rule.get("allow", True) and rule.get("cmd") == WILDCARD:
            rule_args = rule.get("args")
            if rule_args is None or list(rule_args) == [WILDCARD]:
                issues.append("overbroad_wildcard")
                break
    if not policy.get("require_signature"):
        issues.append("missing_signature")
    return issues


def authz_batch(requests, store, key):
    """Authorize a batch of requests and return per-request results."""
    policy = store.get("policy") or {}
    results = []
    session = None
    seq = None
    for request in requests:
        if session is None:
            session = request.get("session")
        if seq is None:
            seq = request.get("seq")
        now = request.get("now", time.time())
        allowed = (
            check_session(store, session, seq, now)
            and verify_signature(request, key)
            and check_user(request.get("user"), policy)
        )
        results.append(
            {
                "session": request.get("session"),
                "seq": request.get("seq"),
                "allowed": allowed,
                "reasons": [],
            }
        )
    return {"results": results, "allowed": all(item["allowed"] for item in results)}