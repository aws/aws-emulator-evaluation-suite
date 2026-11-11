"""converse-guardrail-intervention-stop-reason."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "converse-guardrail-intervention-stop-reason"
GROUP = "e2e"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"
BLOCKED_WORD = "FLIBBERTIGIBBET"


@tags("axis:happy-path", "cap:c4", "cap:c6", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A word guardrail intervenes the same way via ApplyGuardrail, Converse and ConverseStream.
    Clean text passes ApplyGuardrail and Converse, so a path that skips enforcement disagrees."""
    bedrock = ctx.client("bedrock")
    guardrail_id = _create_word_guardrail(ctx, bedrock, BLOCKED_WORD)
    brt = ctx.client("bedrock-runtime")
    guardrail_config = {"guardrailIdentifier": guardrail_id, "guardrailVersion": "DRAFT", "trace": "enabled"}
    blocked_text = f"Please say the word {BLOCKED_WORD} now."
    clean_text = "Please say the word banana now."

    applied_blocked = brt.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": blocked_text}}],
    )
    assert applied_blocked["action"] == "GUARDRAIL_INTERVENED", applied_blocked["action"]
    applied_clean = brt.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": clean_text}}],
    )
    assert applied_clean["action"] == "NONE", applied_clean["action"]

    blocked = brt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": blocked_text}]}],
        guardrailConfig=guardrail_config,
        inferenceConfig={"maxTokens": 64, "temperature": 0},
    )
    assert blocked["stopReason"] == "guardrail_intervened", blocked["stopReason"]

    allowed = brt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": clean_text}]}],
        guardrailConfig=guardrail_config,
        inferenceConfig={"maxTokens": 64, "temperature": 0},
    )
    assert allowed["stopReason"] == "end_turn", allowed["stopReason"]

    stream_resp = brt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": blocked_text}]}],
        guardrailConfig=guardrail_config,
        inferenceConfig={"maxTokens": 64, "temperature": 0},
    )
    stream_stop_reason = None
    for event in stream_resp["stream"]:
        if "messageStop" in event:
            stream_stop_reason = event["messageStop"]["stopReason"]
    assert stream_stop_reason == "guardrail_intervened", stream_stop_reason


def _create_word_guardrail(ctx: Any, bedrock, blocked_word: str) -> str:
    name = ctx.unique_name("sim2real-behav-grd-")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="Blocked by test guardrail.",
        blockedOutputsMessaging="Blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": blocked_word}]},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT")["status"]
        if status == "READY":
            return guardrail_id
        if status == "FAILED":
            raise AssertionError("guardrail creation reported status FAILED")
        time.sleep(1)
    raise AssertionError("guardrail never reached READY status within 30s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
