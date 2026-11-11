"""bedrock-runtime-apply-guardrail-without-the-grounding-source-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-apply-guardrail-without-the-grounding-source-rejected"
GROUP = 'overly-permissive'
SERVICES = ['bedrock', 'bedrock-runtime']

_BLOCKED_IN = "sim2real-cgn-refused-this-input-9e42"
_BLOCKED_OUT = "sim2real-cgn-refused-this-output-9e42"
_READY_TIMEOUT_S = 180
_THRESHOLD = 0.7

_SOURCE = "The Reykjavik office closes at 17:00 on weekdays."
_QUERY = "When does the Reykjavik office close on weekdays?"
_ANSWER = "It closes at 23:00."


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
    status = _poll(lambda: _guardrail_status(bc, gid, version),
                   lambda s: s in ("READY", "FAILED"), timeout_s=_READY_TIMEOUT_S)
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY; last status "
        f"{status!r}"
    )


def _delete_guardrail(bc, gid):
    deadline = time.monotonic() + 60
    while True:
        try:
            bc.delete_guardrail(guardrailIdentifier=gid)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ThrottlingException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _error_code(fn):
    """Return (code, message), or raise if the call unexpectedly succeeded."""
    try:
        resp = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code", ""),
                exc.response.get("Error", {}).get("Message", ""))
    raise AssertionError(
        f"ApplyGuardrail evaluated a contextual-grounding policy with NO grounding source and "
        f"succeeded. That is an over-permissiveness finding, not a code mismatch: any score it "
        f"returned was computed against nothing. response={resp!r}"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ApplyGuardrail with a grounding policy but no grounding_source block is refused with a
    ValidationException naming the missing source; the complete triple is scored before and after.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = bc.create_guardrail(
        name=ctx.unique_name("sim2real-behav-gr-"),
        description="sim2real contextual grounding, missing-qualifier negative",
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        contextualGroundingPolicyConfig={
            "filtersConfig": [{"type": "GROUNDING", "threshold": _THRESHOLD}]},
        tags=[{"key": "sim2real", "value": "guardrail-grounding-negative"},
              {"key": "sim2real:managed", "value": "true"}],
    )
    gid = created["guardrailId"]
    ctx.on_cleanup(lambda: _delete_guardrail(bc, gid))
    _wait_ready(bc, gid)
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    _wait_ready(bc, gid, version)

    source_block = {"text": {"text": _SOURCE, "qualifiers": ["grounding_source"]}}
    query_block = {"text": {"text": _QUERY, "qualifiers": ["query"]}}
    answer_block = {"text": {"text": _ANSWER}}

    # Barrier: the complete triple works and really is scored.
    complete = rt.apply_guardrail(guardrailIdentifier=gid, guardrailVersion=version,
                                  source="OUTPUT",
                                  content=[source_block, query_block, answer_block])
    assert complete["action"] == "GUARDRAIL_INTERVENED", (
        f"the complete grounding triple must be evaluated and intervene on this answer, else the "
        f"refusal below proves nothing; got action={complete['action']!r} "
        f"assessments={complete['assessments']!r}"
    )
    scored = [f for f in ((complete["assessments"][0].get("contextualGroundingPolicy") or {})
                          .get("filters") or [])
              if f.get("type") == "GROUNDING"]
    assert len(scored) == 1 and "score" in scored[0], (
        f"the barrier must produce exactly one scored GROUNDING filter; got "
        f"{complete['assessments'][0]!r}"
    )
    assert complete["usage"]["contextualGroundingPolicyUnits"] == 1, (
        f"the barrier evaluation must bill one contextual-grounding unit; got usage="
        f"{complete['usage']!r}"
    )

    # Break exactly one thing: drop the grounding_source block. Everything else is byte-identical.
    code, message = _error_code(
        lambda: rt.apply_guardrail(guardrailIdentifier=gid, guardrailVersion=version,
                                   source="OUTPUT", content=[query_block, answer_block])
    )
    assert code == "ValidationException", (
        f"a contextual-grounding evaluation with no grounding source must be refused with "
        f"ValidationException; got {code!r} message={message!r}"
    )
    expected_message = (
        "The provided request does not contain the grounding source. Grounding source, query and "
        "content to guard are required for Guardrails contextual grounding policy evaluation."
    )
    assert message == expected_message, (
        f"the refusal must name the missing grounding source so a caller can act on it, rather "
        f"than being a generic validation failure; expected {expected_message!r}, got {message!r}"
    )

    # Re-run the barrier: the refusal was about the dropped block, not an unusable guardrail.
    again = rt.apply_guardrail(guardrailIdentifier=gid, guardrailVersion=version, source="OUTPUT",
                              content=[source_block, query_block, answer_block])
    assert again["action"] == "GUARDRAIL_INTERVENED", (
        f"the complete triple must still be accepted after the refusal; got action="
        f"{again['action']!r} assessments={again['assessments']!r}"
    )
    assert again["usage"]["contextualGroundingPolicyUnits"] == 1, (
        f"the re-run barrier must still bill exactly one unit; got usage={again['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
