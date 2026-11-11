"""bedrock-runtime-guardrail-contextual-grounding-scores-the-answer-against-the-source."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-guardrail-contextual-grounding-scores-the-answer-against-the-source"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock', 'bedrock-runtime']

_BLOCKED_IN = "sim2real-cg-refused-this-input-2d90"
_BLOCKED_OUT = "sim2real-cg-refused-this-output-2d90"
_READY_TIMEOUT_S = 180
_THRESHOLD = 0.7

_SOURCE = "The Reykjavik office closes at 17:00 on weekdays."
_QUERY = "When does the Reykjavik office close on weekdays?"
_ENTAILED = "It closes at 17:00."
_CONTRADICTED = "It closes at 23:00."


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


def _grounding_filter(resp):
    """The single GROUNDING filter finding from the one assessment ApplyGuardrail returns."""
    assessments = resp["assessments"]
    assert len(assessments) == 1, (
        f"one ApplyGuardrail call over one guardrail must return one assessment; got "
        f"{assessments!r}"
    )
    filters = [f for f in
               ((assessments[0].get("contextualGroundingPolicy") or {}).get("filters") or [])
               if f.get("type") == "GROUNDING"]
    assert len(filters) == 1, (
        f"the configured GROUNDING filter must be reported exactly once; got "
        f"assessment {assessments[0]!r}"
    )
    return filters[0]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A contextual-grounding guardrail passes an answer the source entails and blocks one it
    contradicts, scoring the blocked answer below the threshold and below the entailed one; only
    the answer counts as guarded text.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = bc.create_guardrail(
        name=ctx.unique_name("sim2real-behav-gr-"),
        description="sim2real contextual grounding policy",
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        contextualGroundingPolicyConfig={
            "filtersConfig": [{"type": "GROUNDING", "threshold": _THRESHOLD}]},
        tags=[{"key": "sim2real", "value": "guardrail-contextual-grounding"},
              {"key": "sim2real:managed", "value": "true"}],
    )
    gid = created["guardrailId"]
    # One delete for the whole guardrail: a separate per-version delete strands it.
    ctx.on_cleanup(lambda: _delete_guardrail(bc, gid))
    _wait_ready(bc, gid)
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    _wait_ready(bc, gid, version)

    def _apply(answer):
        return rt.apply_guardrail(
            guardrailIdentifier=gid, guardrailVersion=version, source="OUTPUT",
            content=[
                {"text": {"text": _SOURCE, "qualifiers": ["grounding_source"]}},
                {"text": {"text": _QUERY, "qualifiers": ["query"]}},
                {"text": {"text": answer}},
            ])

    # Control first: proves the guardrail is live and does not block everything.
    grounded = _apply(_ENTAILED)
    assert grounded["action"] == "NONE", (
        f"an answer entailed by the grounding source must pass; got action="
        f"{grounded['action']!r} actionReason={grounded.get('actionReason')!r} "
        f"assessments={grounded['assessments']!r}"
    )
    assert grounded["outputs"] == [], (
        f"a non-intervening evaluation must not rewrite the payload; got {grounded['outputs']!r}"
    )
    good = _grounding_filter(grounded)
    assert good["action"] == "NONE" and good["detected"] is False, (
        f"the passing filter must report no detection; got {good!r}"
    )
    assert good["threshold"] == _THRESHOLD, (
        f"the filter must echo the threshold that was configured; got {good!r}"
    )
    assert good["score"] >= good["threshold"], (
        f"a filter that did not intervene must score at or above its own threshold; got {good!r}"
    )

    ungrounded = _apply(_CONTRADICTED)
    assert ungrounded["action"] == "GUARDRAIL_INTERVENED", (
        f"an answer contradicted by the grounding source must intervene; got action="
        f"{ungrounded['action']!r} assessments={ungrounded['assessments']!r}"
    )
    assert ungrounded["actionReason"] == "Guardrail blocked.", (
        f"a grounding intervention is a block, not a mask, and actionReason is the only field "
        f"that says which; got {ungrounded.get('actionReason')!r}"
    )
    assert [o.get("text") for o in ungrounded["outputs"]] == [_BLOCKED_OUT], (
        f"an OUTPUT-source intervention must substitute the configured blockedOutputsMessaging; "
        f"got {ungrounded['outputs']!r}"
    )
    bad = _grounding_filter(ungrounded)
    assert bad["action"] == "BLOCKED" and bad["detected"] is True, (
        f"the intervening filter must be the GROUNDING one, reported as detected and BLOCKED; "
        f"got {bad!r}"
    )
    assert bad["score"] < bad["threshold"], (
        f"an intervening GROUNDING filter must score BELOW its own threshold -- this is the "
        f"invariant that ties the decision to the number, and an emulator reporting a high score "
        f"alongside a block is caught here; got {bad!r}"
    )
    assert bad["score"] < good["score"], (
        f"the answer the source contradicts must score strictly lower than the one it entails; "
        f"contradicted={bad['score']} entailed={good['score']}"
    )

    # Only the answer is guarded text; the grounding source and query count only toward total.
    coverage = ungrounded["guardrailCoverage"]["textCharacters"]
    assert coverage["guarded"] == len(_CONTRADICTED), (
        f"the guarded character count must be the answer alone ({len(_CONTRADICTED)}); got "
        f"{coverage!r}"
    )
    assert coverage["total"] == len(_SOURCE) + len(_QUERY) + len(_CONTRADICTED), (
        f"the total must cover every text block the request carried; got {coverage!r}"
    )
    assert ungrounded["usage"]["contextualGroundingPolicyUnits"] == 1, (
        f"one grounding evaluation must bill one contextual-grounding unit; got usage="
        f"{ungrounded['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
