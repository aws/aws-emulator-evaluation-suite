"""bedrock-guardrail-blocked-input-never-reaches-the-model."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-guardrail-blocked-input-never-reaches-the-model"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']


MODEL_ID = "amazon.nova-lite-v1:0"

_BLOCKED_IN = "sim2real-guardrail-refused-this-input-4f1a"
_BLOCKED_OUT = "sim2real-guardrail-refused-this-output-4f1a"
_READY_TIMEOUT_S = 120

_TOPIC_NAME = "sim2real-crypto-investment-advice"
_TOPIC_DEF = (
    "Requests for advice on which cryptocurrency to buy, sell or hold as an investment, "
    "including price predictions and portfolio allocation."
)
_ON_TOPIC = "Should I buy ethereum as an investment this month?"
_OFF_TOPIC = "What time does the library close on Sunday?"


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


def _delete_guardrail(bc, gid):
    """Delete the guardrail, which also deletes its versions; retry ConflictException to a
    deadline."""
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


def _text(resp):
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """Converse through a DENY-topic guardrail stops an on-topic prompt with guardrail_intervened,
    the blockedInputMessaging text, zero tokens and a BLOCKED topic trace, while an off-topic
    prompt is answered: the input is blocked before the model runs.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = bc.create_guardrail(
        name=ctx.unique_name("sim2real-behav-gr-"),
        description="sim2real denied topic policy, evaluated inline on Converse",
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        topicPolicyConfig={"topicsConfig": [{
            "name": _TOPIC_NAME,
            "definition": _TOPIC_DEF,
            "examples": ["Should I buy bitcoin right now?",
                         "Which altcoin will double this year?"],
            "type": "DENY",
        }]},
        tags=[{"key": "sim2real", "value": "guardrail-blocked-input"}],
    )
    gid = created["guardrailId"]
    ctx.on_cleanup(lambda: _delete_guardrail(bc, gid))
    _wait_ready(bc, gid)

    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    _wait_ready(bc, gid, version)

    guardrail_config = {
        "guardrailIdentifier": gid,
        "guardrailVersion": version,
        "trace": "enabled",
    }

    blocked = rt.converse(
        modelId=MODEL_ID,
        guardrailConfig=guardrail_config,
        messages=[{"role": "user", "content": [{"text": _ON_TOPIC}]}],
        inferenceConfig={"maxTokens": 200, "temperature": 0.0},
    )

    assert blocked["stopReason"] == "guardrail_intervened", (
        f"an on-topic prompt through a DENY-topic guardrail must stop with "
        f"'guardrail_intervened'; got {blocked['stopReason']!r} text={_text(blocked)!r}"
    )
    assert _text(blocked) == _BLOCKED_IN, (
        f"the response must be the configured blockedInputMessaging byte-for-byte; expected "
        f"{_BLOCKED_IN!r} got {_text(blocked)!r}"
    )
    usage = blocked["usage"]
    assert usage["outputTokens"] == 0, (
        f"a blocked INPUT means the model never generated, so no output tokens may be billed -- "
        f"this is what separates a real inline guardrail from a post-hoc output filter; "
        f"usage={usage!r}"
    )
    assert usage["inputTokens"] == 0, (
        f"a blocked input never reaches the model, so no input tokens may be billed either; "
        f"usage={usage!r}"
    )

    assessment = blocked["trace"]["guardrail"]["inputAssessment"][gid]
    topics = (assessment.get("topicPolicy") or {}).get("topics") or []
    hits = [t for t in topics
            if t.get("name") == _TOPIC_NAME and t.get("type") == "DENY"
            and t.get("action") == "BLOCKED"]
    assert hits, (
        f"the trace must name the denied topic {_TOPIC_NAME!r} with type=DENY action=BLOCKED "
        f"rather than merely reporting that something intervened; inputAssessment={assessment!r}"
    )
    applied = assessment["appliedGuardrailDetails"]
    assert applied["guardrailId"] == gid and applied["guardrailVersion"] == version, (
        f"the trace must attribute the block to the guardrail actually passed "
        f"({gid!r}, {version!r}); got {applied!r}"
    )

    # Control through the SAME guardrail version: an unrelated prompt must reach the model and be
    # answered. An emulator that blocks everything, or that stubs guardrailConfig by always
    # returning blockedInputMessaging, fails here.
    control = rt.converse(
        modelId=MODEL_ID,
        guardrailConfig=guardrail_config,
        messages=[{"role": "user", "content": [{"text": _OFF_TOPIC}]}],
        inferenceConfig={"maxTokens": 200, "temperature": 0.0},
    )
    assert control["stopReason"] == "end_turn", (
        f"an off-topic prompt through the same guardrail must be answered normally; got "
        f"{control['stopReason']!r} text={_text(control)!r}"
    )
    assert control["usage"]["outputTokens"] > 0 and _text(control).strip(), (
        f"the control must be a real generation; usage={control['usage']!r} "
        f"text={_text(control)!r}"
    )
    assert _BLOCKED_IN not in _text(control), (
        f"the control answer must not be the blocked-input message; got {_text(control)!r}"
    )
    control_topics = (
        (control["trace"]["guardrail"]["inputAssessment"][gid].get("topicPolicy") or {})
        .get("topics") or []
    )
    assert not [t for t in control_topics if t.get("action") == "BLOCKED"], (
        f"the off-topic control must produce no BLOCKED topic assessment; got {control_topics!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
