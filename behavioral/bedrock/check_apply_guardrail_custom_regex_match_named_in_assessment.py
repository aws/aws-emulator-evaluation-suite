"""apply-guardrail-custom-regex-match-named-in-assessment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-custom-regex-match-named-in-assessment"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']


_BLOCKED_IN = "sim2real-blocked-input-c4d7"
_BLOCKED_OUT = "sim2real-blocked-output-c4d7"
_READY_TIMEOUT_S = 180

_REGEX_NAME = "sim2real-employee-badge"
_REGEX_PATTERN = r"EMP-[0-9]{6}"


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


def _publish_version(bc, ctx, gid):
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    ctx.on_cleanup(
        lambda: bc.delete_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    )
    _wait_ready(bc, gid, version)
    return version


def _apply(rt, gid, version, text):
    """ApplyGuardrail: policy engine only, no model weights (not H1-bounded). One short sentence
    -- ApplyGuardrail bills per text unit."""
    try:
        return rt.apply_guardrail(
            guardrailIdentifier=gid,
            guardrailVersion=version,
            source="INPUT",
            content=[{"text": {"text": text}}],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "AccessDeniedException":
            raise AssertionError(
                "ApplyGuardrail -> AccessDeniedException. bedrock has been reachable in this "
                "sandbox only via AWS_BEARER_TOKEN_BEDROCK, not task-role IAM, so this is an "
                "ENVIRONMENT artifact and not an emulator fidelity signal."
            ) from exc
        raise


def _regex_entries(resp, **fields):
    """assessments[0].sensitiveInformationPolicy.regexes entries matching every field."""
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    entries = (assessments[0].get("sensitiveInformationPolicy") or {}).get("regexes") or []
    return [e for e in entries if all(e.get(k) == v for k, v in fields.items())]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom-regex guardrail round-trips its pattern, blocks EMP-123456 with an assessment naming
    the regex and match, and lets a near miss (EMP-12) and unrelated text pass: a deterministic,
    operator-defined match.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real custom regex policy",
        tags=[{"key": "sim2real", "value": CHECK}],
        sensitiveInformationPolicyConfig={
            "regexesConfig": [
                {
                    "name": _REGEX_NAME,
                    "description": "six-digit employee badge id",
                    "pattern": _REGEX_PATTERN,
                    "action": "BLOCK",
                }
            ]
        },
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)

    # The stored policy must round-trip the pattern verbatim before it can be trusted to fire.
    stored = bc.get_guardrail(guardrailIdentifier=gid)
    regexes = (stored.get("sensitiveInformationPolicy") or {}).get("regexes") or []
    assert [r.get("name") for r in regexes] == [_REGEX_NAME], (
        f"GetGuardrail must return exactly the one configured regex; got {regexes!r}"
    )
    assert regexes[0].get("pattern") == _REGEX_PATTERN, (
        f"stored pattern must be verbatim {_REGEX_PATTERN!r}; got {regexes[0].get('pattern')!r}"
    )

    version = _publish_version(bc, ctx, gid)

    resp = _apply(rt, gid, version, "My badge is EMP-123456.")
    assert resp["action"] == "GUARDRAIL_INTERVENED", (
        f"a matching custom regex must intervene; action={resp['action']!r} "
        f"assessments={resp['assessments']!r}"
    )
    hits = _regex_entries(resp, name=_REGEX_NAME, action="BLOCKED")
    assert hits, (
        f"no regexes assessment entry with name={_REGEX_NAME!r} action=BLOCKED; "
        f"assessments[0]={resp['assessments'][0]!r}"
    )
    assert hits[0].get("match") == "EMP-123456", (
        f"GuardrailRegexFilter.match must be the matched substring 'EMP-123456'; "
        f"got {hits[0].get('match')!r}"
    )

    # Control 1 -- a NEAR MISS (two digits, not six) must not fire. A substring/contains
    # implementation passes the positive case and fails here.
    near = _apply(rt, gid, version, "My badge is EMP-12.")
    assert near["action"] == "NONE", (
        f"'EMP-12' does not match {_REGEX_PATTERN!r} and must not intervene; "
        f"action={near['action']!r} assessments={near['assessments']!r}"
    )
    assert not _regex_entries(near, action="BLOCKED"), (
        f"near-miss text produced a BLOCKED regex assessment: {near['assessments']!r}"
    )

    # Control 2 -- unrelated text must not fire either.
    benign = _apply(rt, gid, version, "The office opens at eight.")
    assert benign["action"] == "NONE", (
        f"benign text must not intervene; action={benign['action']!r} "
        f"assessments={benign['assessments']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
