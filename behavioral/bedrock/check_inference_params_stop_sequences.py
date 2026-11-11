"""inference-params-stop-sequences."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

# A model that honours Converse stopSequences: it truncates its own completion at the sequence
# reproducibly, while some models refuse the field ("This model doesn't support the stopSequences
# field").
MODEL_ID = "us.meta.llama4-scout-17b-instruct-v1:0"

_STOP = "STOP7"
_PROMPT = ("Output exactly the following characters and nothing else, no commentary: "
           "1 2 3 4 5 6 STOP7 8 9")


def _require_model_access(rt):
    try:
        rt.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": "hi"}]}],
            inferenceConfig={"maxTokens": 1},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "") or type(exc).__name__
        raise AssertionError(f"model {MODEL_ID} not usable for inference here ({code})") from exc


def _converse_text(rt, **inference_config):
    resp = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig=inference_config,
    )
    text = "".join(b.get("text", "") for b in resp["output"]["message"]["content"])
    return resp, text


CHECK = "inference-params-stop-sequences"
GROUP = 'inference_params'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse with stopSequences truncates generation at the sequence, not merely accepts the field."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)

    stopped, stopped_text = _converse_text(rt, maxTokens=80, temperature=0.0, stopSequences=[_STOP])
    assert _STOP not in stopped_text, (
        f"the stop sequence {_STOP!r} must not appear in a truncated completion; got {stopped_text!r}"
    )
    assert "8" not in stopped_text and "9" not in stopped_text, (
        f"generation must halt AT the stop sequence, so characters requested after it "
        f"must be absent; got {stopped_text!r}"
    )
    assert "1" in stopped_text and "6" in stopped_text, (
        f"the model must have generated the text BEFORE the stop sequence -- an empty or "
        f"immediately-stopped completion is not a truncation; got {stopped_text!r}"
    )
    assert stopped["usage"]["outputTokens"] > 0, (
        f"a truncated-but-non-empty completion must bill output tokens; "
        f"usage={stopped['usage']!r} text={stopped_text!r}"
    )

    # Control, same prompt and model, stopSequences removed: the tail MUST come back. Without
    # this, a target that ignores stopSequences and just returns a short completion would
    # satisfy every assertion above -- the control forces the tail to exist when nothing asked
    # for it to be cut.
    uncapped, uncapped_text = _converse_text(rt, maxTokens=80, temperature=0.0)
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
