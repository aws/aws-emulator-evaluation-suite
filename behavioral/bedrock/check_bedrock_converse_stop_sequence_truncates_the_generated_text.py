"""bedrock-converse-stop-sequence-truncates-the-generated-text."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bedrock-converse-stop-sequence-truncates-the-generated-text"
GROUP = 'inference_params'
SERVICES = ['bedrock']

# ===== helpers =====
#
# MODEL_ID is pinned: some models reject `stopSequences` outright, and Amazon Nova accepts it but
# leaves the sequence in the text. The Meta Llama 4 Scout model truncates and excludes it reliably.
MODEL_ID = "us.meta.llama4-scout-17b-instruct-v1:0"

_STOP = "STOP7"
_PROMPT = ("Output exactly the following characters and nothing else, no commentary: "
           "1 2 3 4 5 6 STOP7 8 9")


def _converse_text(rt, **extra):
    cfg = {"maxTokens": 80, "temperature": 0.0}
    cfg.update(extra)
    resp = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig=cfg,
    )
    text = "".join(b.get("text", "") for b in resp["output"]["message"]["content"])
    return resp, text


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A Converse stopSequence truncates the model's freshly generated text at the sequence: the
    tail is absent with the sequence and present in an uncapped control of the same prompt, so a
    canned short reply cannot pass. stopReason is 'end_turn', as AWS reports it for this model.
    """
    rt = ctx.client("bedrock-runtime")

    stopped, stopped_text = _converse_text(rt, stopSequences=[_STOP])

    assert stopped["stopReason"] == "end_turn", (
        f"a stopSequences truncation reports stopReason 'end_turn' on every model reachable "
        f"here; got {stopped['stopReason']!r} with text {stopped_text!r}"
    )
    assert _STOP not in stopped_text, (
        f"the stop sequence {_STOP!r} must not appear in the truncated completion; "
        f"got {stopped_text!r}"
    )
    assert "8" not in stopped_text and "9" not in stopped_text, (
        f"generation must halt AT the stop sequence, so the characters the prompt asked for "
        f"after it ('8', '9') must be absent; got {stopped_text!r}"
    )
    assert "1" in stopped_text and "6" in stopped_text, (
        f"the model must have generated the text BEFORE the stop sequence -- an empty or "
        f"immediately-stopped completion is not a truncation; got {stopped_text!r}"
    )
    assert stopped["usage"]["outputTokens"] > 0, (
        f"a truncated-but-non-empty completion must bill output tokens; "
        f"usage={stopped['usage']!r} text={stopped_text!r}"
    )

    # Control, same prompt and same model, stopSequences removed: the tail MUST come back.
    # This is what makes every assertion above falsifiable rather than satisfiable by silence.
    uncapped, uncapped_text = _converse_text(rt)
    assert _STOP in uncapped_text, (
        f"without stopSequences the model must emit the sequence it was asked to print, "
        f"otherwise the truncation above proves nothing; got {uncapped_text!r}"
    )
    assert "8" in uncapped_text and "9" in uncapped_text, (
        f"without stopSequences the tail after {_STOP!r} must be present; got {uncapped_text!r}"
    )
    assert uncapped["usage"]["outputTokens"] > stopped["usage"]["outputTokens"], (
        f"the untruncated completion must bill MORE output tokens than the truncated one; "
        f"uncapped={uncapped['usage']!r} truncated={stopped['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
