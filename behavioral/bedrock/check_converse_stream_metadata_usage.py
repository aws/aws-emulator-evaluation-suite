"""converse-stream-metadata-usage."""
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

CHECK = "converse-stream-metadata-usage"
GROUP = 'converse_stream'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream metadata event contains usage with inputTokens and outputTokens."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = rt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": "Hi."}]}],
        inferenceConfig={"maxTokens": 10})
    metadata_event = None
    for event in resp["stream"]:
        if "metadata" in event:
            metadata_event = event["metadata"]
            break
    assert metadata_event is not None, "No metadata event received in stream"
    usage = metadata_event.get("usage", {})
    assert "inputTokens" in usage, f"metadata.usage missing inputTokens. Got: {usage}"
    assert "outputTokens" in usage, f"metadata.usage missing outputTokens. Got: {usage}"
    assert usage["inputTokens"] > 0, f"expected inputTokens > 0, got {usage['inputTokens']}"
    assert usage["outputTokens"] > 0, f"expected outputTokens > 0, got {usage['outputTokens']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
