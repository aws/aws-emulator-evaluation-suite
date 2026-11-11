"""converse-stream-event-types."""
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

CHECK = "converse-stream-event-types"
GROUP = 'converse_stream'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream emits messageStart, contentBlockDelta, contentBlockStop, messageStop, and metadata."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = rt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": "Say hi."}]}],
        inferenceConfig={"maxTokens": 50})
    stream = resp["stream"]
    event_types_seen: set[str] = set()
    for event in stream:
        event_types_seen.update(event.keys())
    # contentBlockStop is reliably emitted for a plain-text content block; contentBlockStart is not,
    # since a plain-text block needs no start metadata, so it stays out of this required set.
    required = {"messageStart", "contentBlockDelta", "contentBlockStop", "messageStop", "metadata"}
    missing = required - event_types_seen
    assert not missing, f"Missing required stream event types: {missing}. Seen: {event_types_seen}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
