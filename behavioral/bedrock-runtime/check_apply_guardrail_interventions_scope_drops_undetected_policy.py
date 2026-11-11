"""apply-guardrail-interventions-scope-drops-undetected-policy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-interventions-scope-drops-undetected-policy"
GROUP = 'apply_guardrail'
SERVICES = ['bedrock-runtime']

_TOPIC = "SimRealFinancialAdvice"
_BENIGN = "The sky is blue today."
_READY_TIMEOUT_S = 120.0


def _await_ready(bc, gid):
    deadline = time.monotonic() + _READY_TIMEOUT_S
    status = bc.get_guardrail(guardrailIdentifier=gid)["status"]
    while status != "READY":
        assert status != "FAILED", f"guardrail {gid!r} entered FAILED while being created"
        assert time.monotonic() < deadline, (
            f"guardrail {gid!r} never reached READY within {_READY_TIMEOUT_S}s; "
            f"last status was {status!r}"
        )
        time.sleep(3.0)
        status = bc.get_guardrail(guardrailIdentifier=gid)["status"]


def _apply(rt, gid, scope):
    deadline = time.monotonic() + _READY_TIMEOUT_S
    while True:
        try:
            return rt.apply_guardrail(
                guardrailIdentifier=gid,
                guardrailVersion="DRAFT",
                source="INPUT",
                outputScope=scope,
                content=[{"text": {"text": _BENIGN}}],
            )
        except ClientError as exc:
            # A guardrail reported READY by the control plane is briefly not yet applicable on the
            # runtime endpoint. Retry only that, and only while the budget lasts.
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            assert time.monotonic() < deadline, (
                f"guardrail {gid!r} was READY but ApplyGuardrail kept reporting it absent for "
                f"{_READY_TIMEOUT_S}s"
            )
            time.sleep(5.0)


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApplyGuardrail outputScope=FULL reports the undetected denied topic; INTERVENTIONS omits it.

    For the same benign input, the INTERVENTIONS assessment drops the whole topicPolicy member,
    while action, usage, coverage and guardrail attribution match FULL."""
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = bc.create_guardrail(
        name=ctx.unique_name("sim2real-behav-brt-gr-"),
        description="sim2real: one denied topic, read back under both ApplyGuardrail output scopes",
        blockedInputMessaging="Blocked input.",
        blockedOutputsMessaging="Blocked output.",
        tags=[{"key": "sim2real", "value": "behavioral"}],
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": _TOPIC,
                    "definition": "Advice about investing money or picking individual stocks.",
                    "examples": ["Which stock should I buy?"],
                    "type": "DENY",
                }
            ]
        },
    )
    gid = created["guardrailId"]
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=gid))
    _await_ready(bc, gid)

    full = _apply(rt, gid, "FULL")
    interventions = _apply(rt, gid, "INTERVENTIONS")

    for scope, resp in (("FULL", full), ("INTERVENTIONS", interventions)):
        assert resp["action"] == "NONE", (
            f"{scope}: benign text {_BENIGN!r} produced action {resp['action']!r}"
        )
        assert resp["outputs"] == [], (
            f"{scope}: an unintervened verdict must carry no outputs, got {resp['outputs']!r}"
        )
        assert len(resp["assessments"]) == 1, (
            f"{scope}: expected one assessment for one guardrail, got {len(resp['assessments'])}"
        )

    full_assessment = full["assessments"][0]
    lean_assessment = interventions["assessments"][0]

    # FULL carries the non-detection as evidence.
    topics = full_assessment["topicPolicy"]["topics"]
    assert [t["name"] for t in topics] == [_TOPIC], (
        f"FULL assessment named topics {[t['name'] for t in topics]!r}, expected [{_TOPIC!r}]"
    )
    assert topics[0]["detected"] is False, (
        f"benign text tripped the denied topic: {topics[0]!r}"
    )
    assert topics[0]["action"] == "NONE", (
        f"an undetected topic must carry action NONE, got {topics[0]['action']!r}"
    )
    assert topics[0]["type"] == "DENY", (
        f"the configured topic type was DENY, assessment reported {topics[0]['type']!r}"
    )

    # INTERVENTIONS drops it entirely -- not an empty topics list, the member itself is absent.
    assert "topicPolicy" not in lean_assessment, (
        f"INTERVENTIONS must omit a policy that did not intervene, but topicPolicy was present as "
        f"{lean_assessment['topicPolicy']!r}"
    )

    # ...while everything that is not per-policy evidence survives the narrowing unchanged.
    assert full["usage"] == interventions["usage"], (
        f"outputScope must not change billing: FULL reported {full['usage']!r}, "
        f"INTERVENTIONS {interventions['usage']!r}"
    )
    assert full["usage"]["topicPolicyUnits"] == 1, (
        f"one topic policy was evaluated, usage reported "
        f"{full['usage']['topicPolicyUnits']!r} units"
    )
    assert (
        full_assessment["invocationMetrics"]["guardrailCoverage"]
        == lean_assessment["invocationMetrics"]["guardrailCoverage"]
    ), (
        f"outputScope must not change coverage: FULL "
        f"{full_assessment['invocationMetrics']['guardrailCoverage']!r}, INTERVENTIONS "
        f"{lean_assessment['invocationMetrics']['guardrailCoverage']!r}"
    )
    assert full["guardrailCoverage"]["textCharacters"]["guarded"] == len(_BENIGN), (
        f"all {len(_BENIGN)} characters were submitted, coverage reported "
        f"{full['guardrailCoverage']['textCharacters']!r}"
    )
    assert (
        full_assessment["appliedGuardrailDetails"]["guardrailId"]
        == lean_assessment["appliedGuardrailDetails"]["guardrailId"]
        == gid
    ), (
        f"both scopes must attribute the verdict to {gid!r}; got "
        f"{full_assessment['appliedGuardrailDetails']['guardrailId']!r} and "
        f"{lean_assessment['appliedGuardrailDetails']['guardrailId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
