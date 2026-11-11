"""converse-stream-reassembly-matches-stop-reason."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-stream-reassembly-matches-stop-reason"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream delivers text deltas that reassemble into a coherent response, ending
    in a messageStop event carrying the same stopReason enum Converse would return, followed by
    a metadata event with non-zero token usage."""
    brt = ctx.client("bedrock-runtime")
    resp = brt.converse_stream(
        modelId=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": [{"text": "Reply with exactly the single word PONG and nothing else."}],
            }
        ],
        inferenceConfig={"maxTokens": 32, "temperature": 0},
    )

    text_chunks: list[str] = []
    stop_reason = None
    usage = None
    saw_message_start = False
    saw_content_block_stop = False

    for event in resp["stream"]:
        if "messageStart" in event:
            saw_message_start = True
        elif "contentBlockDelta" in event:
            delta = event["contentBlockDelta"]["delta"]
            if "text" in delta:
                text_chunks.append(delta["text"])
        elif "contentBlockStop" in event:
            saw_content_block_stop = True
        elif "messageStop" in event:
            stop_reason = event["messageStop"]["stopReason"]
        elif "metadata" in event:
            usage = event["metadata"]["usage"]
        elif "internalServerException" in event or "modelStreamErrorException" in event:
            raise AssertionError(f"unexpected mid-stream error event: {event}")

    assert saw_message_start, "expected a messageStart event"
    assert saw_content_block_stop, "expected a contentBlockStop event"
    full_text = "".join(text_chunks)
    assert "pong" in full_text.lower(), f"expected PONG in reassembled text, got: {full_text!r}"
    assert usage is not None, "expected a metadata event carrying usage"
    assert usage["totalTokens"] > 0, f"expected non-zero totalTokens, got usage={usage!r}"

    # The docstring's claim is that ConverseStream's stopReason matches what Converse would
    # return for the same input -- that is a cross-operation reconciliation, not a fixed literal,
    # so it must be measured against a live unary call rather than pinned to "end_turn".
    unary = brt.converse(
        modelId=MODEL_ID,
        messages=[
            {
                "role": "user",
                "content": [{"text": "Reply with exactly the single word PONG and nothing else."}],
            }
        ],
        inferenceConfig={"maxTokens": 32, "temperature": 0},
    )
    assert stop_reason == unary["stopReason"], (
        f"ConverseStream stopReason {stop_reason!r} must match Converse's stopReason "
        f"{unary['stopReason']!r} for the same input"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
