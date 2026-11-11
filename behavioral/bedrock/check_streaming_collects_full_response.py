"""streaming-collects-full-response."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

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

CHECK = "streaming-collects-full-response"
GROUP = 'e2e_workflows'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream delivers a long-enough answer across multiple chunks, and
    concatenating them reconstructs a coherent full response."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = rt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [
            {"text": "Write a three sentence story about a lighthouse keeper."}
        ]}],
        inferenceConfig={"maxTokens": 300})
    text_parts: list[str] = []
    for event in resp["stream"]:
        if "contentBlockDelta" in event:
            delta = event["contentBlockDelta"].get("delta", {})
            text = delta.get("text")
            if text:
                text_parts.append(text)
    full_text = "".join(text_parts)
    # ConverseStream returns a multi-sentence answer as several contentBlockDelta events;
    # a single-chunk response means nothing was actually streamed.
    assert len(text_parts) > 1, (
        f"expected the response to arrive as multiple contentBlockDelta chunks, "
        f"got {len(text_parts)}: {text_parts!r}"
    )
    # A three-sentence story is far longer than 80 characters; a stub emitting a token
    # or two is not.
    assert len(full_text) >= 80, (
        f"reconstructed streaming text too short for a three-sentence story: {full_text!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
