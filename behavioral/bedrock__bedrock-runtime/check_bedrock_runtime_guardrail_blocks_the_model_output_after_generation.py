"""bedrock-runtime-guardrail-blocks-the-model-output-after-generation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-guardrail-blocks-the-model-output-after-generation"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock', 'bedrock-runtime']

# One delete registration for the guardrail: it cascades to its versions, and a per-version
# delete registered as well strands the guardrail.
#
# Pinned rather than read from the environment: the check needs a model that answers the
# arithmetic prompt with the single blocked word.
MODEL_ID = "amazon.nova-lite-v1:0"

_BLOCKED_IN = "sim2real-guardrail-refused-this-input-7b3e"
_BLOCKED_OUT = "sim2real-guardrail-refused-this-output-7b3e"
_READY_TIMEOUT_S = 180

#: The word the model must SAY. It appears nowhere in either prompt, so the input side of the
#: guardrail cannot fire -- which is the whole point: only the OUTPUT can be the trigger.
_BLOCKED_WORD = "four"
_ASK_BLOCKED = ("Reply with only the lowercase English word for the result of 2+2. "
                "No punctuation, no other words.")
_ASK_ALLOWED = ("Reply with only the lowercase English word for the result of 2+3. "
                "No punctuation, no other words.")
_INFERENCE = {"maxTokens": 20, "temperature": 0.0}


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
    """Delete the guardrail, retrying while a version delete is still in flight."""
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An output-side guardrail lets the model generate (tokens billed), then replaces its answer
    with blockedOutputsMessaging while the trace's modelOutput keeps the original completion.
    An allowed question and the same question without the guardrail are the controls.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = bc.create_guardrail(
        name=ctx.unique_name("sim2real-behav-gr-"),
        description="sim2real output word policy, evaluated inline on Converse",
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        wordPolicyConfig={"wordsConfig": [{"text": _BLOCKED_WORD}]},
        tags=[{"key": "sim2real", "value": "guardrail-output-block"},
              {"key": "sim2real:managed", "value": "true"}],
    )
    gid = created["guardrailId"]
    ctx.on_cleanup(lambda: _delete_guardrail(bc, gid))
    _wait_ready(bc, gid)
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    _wait_ready(bc, gid, version)

    guardrail_config = {"guardrailIdentifier": gid, "guardrailVersion": version,
                        "trace": "enabled"}

    # Control 1, run FIRST as the barrier: the guardrail is live and does NOT block an answer that
    # avoids the word. Until this succeeds, an intervention below could be "not ready yet".
    allowed = rt.converse(modelId=MODEL_ID, guardrailConfig=guardrail_config,
                          messages=[{"role": "user", "content": [{"text": _ASK_ALLOWED}]}],
                          inferenceConfig=_INFERENCE)
    assert allowed["stopReason"] == "end_turn", (
        f"an answer that does not contain the blocked word must pass; got "
        f"{allowed['stopReason']!r} text={_text(allowed)!r}"
    )
    assert _text(allowed).strip() and _BLOCKED_OUT not in _text(allowed), (
        f"the control must be the model's own answer, not the canned message; got "
        f"{_text(allowed)!r}"
    )
    allowed_out = allowed["trace"]["guardrail"].get("outputAssessments", {}).get(gid) or []
    assert allowed_out, (
        f"the OUTPUT side must be assessed even when nothing is detected -- an absent "
        f"outputAssessments means the completion was never evaluated; trace="
        f"{allowed['trace']['guardrail']!r}"
    )
    assert not any("wordPolicy" in a for a in allowed_out), (
        f"the passing answer must produce no wordPolicy finding; got {allowed_out!r}"
    )

    # The subject: an answer whose only content IS the blocked word.
    blocked = rt.converse(modelId=MODEL_ID, guardrailConfig=guardrail_config,
                          messages=[{"role": "user", "content": [{"text": _ASK_BLOCKED}]}],
                          inferenceConfig=_INFERENCE)
    assert blocked["stopReason"] == "guardrail_intervened", (
        f"a completion containing the blocked word must stop with 'guardrail_intervened'; got "
        f"{blocked['stopReason']!r} text={_text(blocked)!r}"
    )
    assert _text(blocked) == _BLOCKED_OUT, (
        f"an OUTPUT-side intervention must substitute blockedOutputsMessaging byte-for-byte -- "
        f"NOT blockedInputMessaging, which is how a caller distinguishes the two; expected "
        f"{_BLOCKED_OUT!r} got {_text(blocked)!r}"
    )
    assert _BLOCKED_WORD not in _text(blocked), (
        f"the substituted answer must not leak the blocked word; got {_text(blocked)!r}"
    )

    # The model did run: an input-side block bills zero tokens, an output-side block does not.
    usage = blocked["usage"]
    assert usage["inputTokens"] > 0, (
        f"an OUTPUT-side block happens after the prompt reached the model, so input tokens must "
        f"be billed; usage={usage!r}"
    )
    assert usage["outputTokens"] > 0, (
        f"an OUTPUT-side block happens after generation, so output tokens must be billed -- zero "
        f"here would mean the completion the guardrail rejected was never produced; usage={usage!r}"
    )

    guardrail_trace = blocked["trace"]["guardrail"]
    model_output = guardrail_trace.get("modelOutput") or []
    assert model_output, (
        f"an OUTPUT-side intervention must report the completion it suppressed in "
        f"trace.guardrail.modelOutput; that member is the only evidence a caller has that the "
        f"model ran at all; trace keys {sorted(guardrail_trace)!r}"
    )
    assert any(_BLOCKED_WORD in m for m in model_output), (
        f"the suppressed completion must be the one that contained {_BLOCKED_WORD!r}; got "
        f"{model_output!r}"
    )

    findings = [w
                for assessment in (guardrail_trace.get("outputAssessments", {}).get(gid) or [])
                for w in ((assessment.get("wordPolicy") or {}).get("customWords") or [])]
    hits = [w for w in findings
            if w.get("match") == _BLOCKED_WORD and w.get("action") == "BLOCKED"
            and w.get("detected") is True]
    assert hits, (
        f"the OUTPUT assessment must name the matched word with action=BLOCKED detected=True "
        f"rather than merely reporting that something intervened; outputAssessments="
        f"{guardrail_trace.get('outputAssessments')!r}"
    )
    input_findings = [
        w for w in (((guardrail_trace.get("inputAssessment") or {}).get(gid) or {})
                    .get("wordPolicy") or {}).get("customWords") or []
    ]
    assert not input_findings, (
        f"the prompt never contained the blocked word, so the INPUT assessment must report no "
        f"word findings -- an emulator that evaluates one policy against both directions is "
        f"caught here; got {input_findings!r}"
    )

    # Control 2: the identical question with NO guardrailConfig must return the blocked word, which
    # is what proves the word is the model's own answer and the guardrail is what removed it.
    unguarded = rt.converse(modelId=MODEL_ID,
                            messages=[{"role": "user", "content": [{"text": _ASK_BLOCKED}]}],
                            inferenceConfig=_INFERENCE)
    assert unguarded["stopReason"] == "end_turn", (
        f"without the guardrail the same question must be answered normally; got "
        f"{unguarded['stopReason']!r} text={_text(unguarded)!r}"
    )
    assert _BLOCKED_WORD in _text(unguarded).lower(), (
        f"the unguarded control must produce the word the guardrail blocked, otherwise the "
        f"intervention above cannot be attributed to the guardrail; got {_text(unguarded)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
