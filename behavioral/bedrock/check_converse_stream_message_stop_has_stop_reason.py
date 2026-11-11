"""converse-stream-message-stop-has-stop-reason."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "amazon.nova-lite-v1:0"

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

CHECK = "converse-stream-message-stop-has-stop-reason"
GROUP = 'converse_stream'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream messageStop event contains stopReason."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = rt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": "Hi."}]}],
        inferenceConfig={"maxTokens": 10})
    for event in resp["stream"]:
        if "messageStop" in event:
            stop = event["messageStop"]
            assert "stopReason" in stop, f"messageStop missing stopReason. Got: {stop}"
            assert stop["stopReason"] in ("end_turn", "max_tokens", "stop_sequence"), (
                f"Unexpected stopReason in messageStop: {stop['stopReason']}"
            )
            return
    raise AssertionError("No messageStop event received in stream")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
