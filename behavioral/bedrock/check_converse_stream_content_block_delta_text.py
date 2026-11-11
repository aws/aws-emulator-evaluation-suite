"""converse-stream-content-block-delta-text."""
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

CHECK = "converse-stream-content-block-delta-text"
GROUP = 'converse_stream'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream emits contentBlockDelta events carrying a delta with non-empty text, and
    the metadata event reports positive usage.outputTokens, at least one per text-bearing chunk.
    """
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = rt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": "Say hello world."}]}],
        inferenceConfig={"maxTokens": 20})
    deltas: list[str] = []
    metadata = None
    for event in resp["stream"]:
        if "contentBlockDelta" in event:
            block = event["contentBlockDelta"]
            assert "delta" in block, f"contentBlockDelta event missing 'delta': {block}"
            text = block["delta"].get("text")
            if text:
                deltas.append(text)
        elif "metadata" in event:
            metadata = event["metadata"]
    assert len(deltas) > 0, "No text deltas received in contentBlockDelta events"
    full_text = "".join(deltas)
    assert len(full_text) > 0, "Concatenated delta text is empty"
    assert metadata is not None, "No metadata event received in stream"
    output_tokens = metadata.get("usage", {}).get("outputTokens", 0)
    assert output_tokens > 0, f"metadata.usage.outputTokens should be positive, got {metadata}"
    assert output_tokens >= len(deltas), (
        f"stream reported {len(deltas)} text-bearing delta chunks but only {output_tokens} "
        f"output tokens; each delta chunk must carry at least one token"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
