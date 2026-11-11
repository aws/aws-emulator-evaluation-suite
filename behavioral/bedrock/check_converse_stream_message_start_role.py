"""converse-stream-message-start-role."""
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

CHECK = "converse-stream-message-start-role"
GROUP = 'converse_stream'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream messageStart event contains role='assistant'."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = rt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": "Hi."}]}],
        inferenceConfig={"maxTokens": 10})
    for event in resp["stream"]:
        if "messageStart" in event:
            assert event["messageStart"].get("role") == "assistant", (
                f"messageStart.role should be 'assistant', got {event['messageStart']}"
            )
            return
    raise AssertionError("No messageStart event received in stream")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
