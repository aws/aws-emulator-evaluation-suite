"""guardrail-malformed-custom-regex-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-malformed-custom-regex-rejected"
GROUP = 'guardrails'
SERVICES = ['bedrock']


_BLOCKED_IN = "sim2real-blocked-input-7d38"
_BLOCKED_OUT = "sim2real-blocked-output-7d38"
_READY_TIMEOUT_S = 180

_REGEX_NAME = "sim2real-badge"
# Exactly one thing is broken: the character class is never closed. `pattern` carries only
# length(1..500) in Smithy -- no `smithy.api#pattern` -- so botocore cannot reject this
# client-side and the request genuinely reaches the server.
_BAD_PATTERN = r"EMP-[0-9{6}"
_GOOD_PATTERN = r"EMP-[0-9]{6}"


def _poll(fn, pred, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _guardrail_status(bc, gid, version=None):
    kw = {"guardrailIdentifier": gid}
    if version is not None:
        kw["guardrailVersion"] = version
    try:
        return bc.get_guardrail(**kw)["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "ABSENT"
        raise


def _wait_ready(bc, gid, version=None):
    status = _poll(
        lambda: _guardrail_status(bc, gid, version),
        lambda s: s in ("READY", "FAILED"),
        timeout_s=_READY_TIMEOUT_S,
    )
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY; "
        f"last status={status!r}"
    )


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-gr-"))
    kwargs.setdefault("blockedInputMessaging", _BLOCKED_IN)
    kwargs.setdefault("blockedOutputsMessaging", _BLOCKED_OUT)
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _list_guardrail_names(bc):
    """Every guardrail name visible to the caller, following nextToken to the terminal page."""
    names, token = [], None
    while True:
        kw = {"maxResults": 100}
        if token:
            kw["nextToken"] = token
        page = bc.list_guardrails(**kw)
        names.extend(g.get("name") for g in page.get("guardrails") or [])
        token = page.get("nextToken")
        if not token:
            return names


def _regex_config(name, pattern):
    return {
        "regexesConfig": [
            {
                "name": name,
                "description": "six-digit employee badge id",
                "pattern": pattern,
                "action": "BLOCK",
            }
        ]
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGuardrail with an uncompilable custom regex returns ValidationException 'Regex pattern is
    invalid.' and lists no guardrail of that name, while the same request with a valid pattern
    becomes READY, stores the pattern verbatim and is listed: the pattern is compiled, not stored.
    """
    bc = ctx.client("bedrock")

    name = ctx.unique_name("sim2real-behav-gr-")

    # --- break exactly one thing: the regex pattern ---
    try:
        bad = bc.create_guardrail(
            name=name,
            description="sim2real malformed regex",
            blockedInputMessaging=_BLOCKED_IN,
            blockedOutputsMessaging=_BLOCKED_OUT,
            sensitiveInformationPolicyConfig=_regex_config(_REGEX_NAME, _BAD_PATTERN),
            tags=[{"key": "sim2real", "value": "guardrail-malformed-regex"}],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ValidationException", (
            f"an uncompilable regex pattern {_BAD_PATTERN!r} must be rejected with "
            f"ValidationException; got {code!r} / {message!r}"
        )
        expected = "Regex pattern is invalid."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        # Register cleanup FIRST so a wrongly-accepted guardrail is never leaked, then fail.
        ctx.on_cleanup(
            lambda: bc.delete_guardrail(guardrailIdentifier=bad["guardrailId"])
        )
        raise AssertionError(
            f"CreateGuardrail accepted the uncompilable pattern {_BAD_PATTERN!r} and returned "
            f"guardrailId={bad['guardrailId']!r}. Either the pattern is validated asynchronously "
            f"(check for GuardrailStatus.FAILED and retarget this assertion) or config is not "
            f"validated at all."
        )

    # --- effect absent: the rejected create left nothing behind ---
    assert name not in _list_guardrail_names(bc), (
        f"a rejected CreateGuardrail must not create the guardrail, but {name!r} appears in "
        f"ListGuardrails"
    )

    # --- control: the same request with only the pattern fixed succeeds and round-trips ---
    created = _create_guardrail(
        bc,
        ctx,
        name=name,
        description="sim2real malformed regex control",
        sensitiveInformationPolicyConfig=_regex_config(_REGEX_NAME, _GOOD_PATTERN),
        tags=[{"key": "sim2real", "value": "guardrail-malformed-regex"}],
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)

    stored = bc.get_guardrail(guardrailIdentifier=gid)
    regexes = (stored.get("sensitiveInformationPolicy") or {}).get("regexes") or []
    assert [r.get("name") for r in regexes] == [_REGEX_NAME], (
        f"control guardrail must hold exactly the one valid regex; got {regexes!r}"
    )
    assert regexes[0].get("pattern") == _GOOD_PATTERN, (
        f"control pattern must round-trip verbatim {_GOOD_PATTERN!r}; "
        f"got {regexes[0].get('pattern')!r}"
    )
    assert name in _list_guardrail_names(bc), (
        f"the accepted guardrail {name!r} must appear in ListGuardrails, proving the earlier "
        f"absence was the rejection and not a broken listing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
