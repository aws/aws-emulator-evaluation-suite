"""response-stream-chunk-ordering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "response-stream-chunk-ordering"
GROUP = "ordering"
SERVICES = ["bedrock-runtime"]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream delivers content chunks in strict generation order with no reordering or duplication."""
    br = ctx.client("bedrock-runtime")
    resp = br.converse_stream(
        modelId="amazon.nova-lite-v1:0",
        messages=[
            {
                "role": "user",
                "content": [
                    {"text": "Write a short five-sentence story about a lighthouse keeper."}
                ],
            }
        ],
        inferenceConfig={"maxTokens": 300},
    )

    events = list(resp["stream"])
    assert events, "expected at least one stream event"

    kinds = [next(iter(event)) for event in events]
    assert kinds[0] == "messageStart", f"first event should be messageStart, got {kinds[0]}"
    assert kinds[-1] == "metadata", f"last event should be metadata, got {kinds[-1]}"
    assert "messageStop" in kinds, "stream must contain a messageStop event"

    stop_idx = kinds.index("messageStop")
    metadata_idx = kinds.index("metadata")
    assert stop_idx < metadata_idx, "messageStop must precede the trailing metadata event"

    delta_positions = [i for i, k in enumerate(kinds) if k == "contentBlockDelta"]
    assert delta_positions, "expected at least one contentBlockDelta event"
    assert delta_positions[0] > 0, "no content delta may precede messageStart"
    assert delta_positions[-1] < stop_idx, "no content delta may follow messageStop"

    delta_events = [events[i]["contentBlockDelta"] for i in delta_positions]
    block_indices = [d["contentBlockIndex"] for d in delta_events]
    assert block_indices == sorted(block_indices), (
        "contentBlockIndex values must be non-decreasing across the stream (no reordering)"
    )

    text = "".join(d["delta"]["text"] for d in delta_events if "text" in d["delta"])
    assert len(text) > 0, "reconstructed text from ordered deltas must be non-empty"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
