"""Public regression tests for the TACACS+ authorization pipeline."""

import hashlib
import hmac
import json

from engine.tac.authz import (
    authz_batch,
    check_command,
    check_session,
    check_user,
    parse_request,
    verify_signature,
)

KEY = "public-test-key"
SIGNED_FIELDS = ("session", "seq", "user", "service", "cmd", "args")


def sign(request, key=KEY):
    body = {name: request.get(name) for name in SIGNED_FIELDS}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed = dict(request)
    signed["signature"] = hmac.new(
        key.encode("utf-8"), blob, hashlib.sha256
    ).hexdigest()
    return signed


def request(**overrides):
    payload = {
        "session": "sess-1",
        "seq": 1,
        "user": "netops",
        "service": "shell",
        "cmd": "show",
        "args": ["version"],
    }
    payload.update(overrides)
    return payload


def policy():
    return {
        "users": {"allow": ["netops"], "deny": ["guest"]},
        "services": {"allow": ["shell"], "deny": ["tacacs"]},
        "commands": [{"cmd": "show", "args": ["version"], "allow": True}],
        "require_signature": True,
    }


def test_public_parse_request_and_signature():
    raw = sign(request(session="sess-parse", seq=3))
    parsed = parse_request(json.dumps(raw))

    assert parsed["session"] == "sess-parse"
    assert parsed["seq"] == 3
    assert parsed["user"] == "netops"
    assert parsed["service"] == "shell"
    assert parsed["cmd"] == "show"
    assert parsed["args"] == ["version"]
    assert parsed["signature"] == raw["signature"]
    assert verify_signature(parsed, KEY) is True

    tampered = dict(parsed)
    tampered["cmd"] = "reload"
    assert verify_signature(tampered, KEY) is False


def test_public_session_rejects_replayed_sequence():
    store = {"sessions": {}}

    assert check_session(store, "sess-replay", 7, 1000) is True
    assert check_session(store, "sess-replay", 7, 1001) is False


def test_public_user_dimension_denies_blocked_user():
    users = {"users": {"allow": ["*"], "deny": ["guest"]}}

    assert check_user("netops", users) is True
    assert check_user("guest", users) is False


def test_public_command_requires_exact_name():
    commands = {"commands": [{"cmd": "show", "args": ["version"], "allow": True}]}

    assert check_command("show", ["version"], commands) is True
    assert check_command("show-secrets", ["version"], commands) is False


def test_public_batch_keeps_requests_independent():
    store = {"policy": policy(), "sessions": {}}
    requests = [
        sign(request(session="sess-batch-a", seq=1)),
        sign(request(session="sess-batch-b", seq=2)),
    ]

    outcome = authz_batch(requests, store, KEY)

    assert [item["allowed"] for item in outcome["results"]] == [True, True]
    assert outcome["allowed"] is True
    sessions = store.get("sessions") or {}
    assert set(sessions) == {"sess-batch-a", "sess-batch-b"}
    assert 1 in sessions["sess-batch-a"]["seen"]
    assert 2 in sessions["sess-batch-b"]["seen"]