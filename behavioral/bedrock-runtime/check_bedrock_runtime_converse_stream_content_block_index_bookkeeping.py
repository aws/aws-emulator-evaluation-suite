"""bedrock-runtime-converse-stream-content-block-index-bookkeeping."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bedrock-runtime-converse-stream-content-block-index-bookkeeping"
GROUP = 'streaming'
SERVICES = ['bedrock-runtime']

# Pinned rather than configurable: the asserted behaviour is per model. This model is invocable
# on demand by its bare id.
MODEL_ID = "amazon.nova-lite-v1:0"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 64, "temperature": 0.0}


def _keys(event):
    """The single top-level key of one event-stream frame."""
    ks = list(event)
    assert len(ks) == 1, f"an event-stream frame must carry exactly one key; got {event!r}"
    return ks[0]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream frames obey contentBlockIndex bookkeeping and reconcile with Converse.
    One messageStart/messageStop, dense non-decreasing indices with one stop each, metadata last,
    and identical inputTokens for the streamed and unary call over the same messages.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html
    """
    rt = ctx.client("bedrock-runtime")

    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    # The stream is single-pass: iterate exactly once and keep every frame in arrival order.
    resp = rt.converse_stream(modelId=MODEL_ID, messages=messages, inferenceConfig=_INFERENCE)
    events = list(resp["stream"])
    order = [_keys(e) for e in events]

    assert order[0] == "messageStart", (
        f"the stream must open with messageStart; observed order {order!r}"
    )
    assert order.count("messageStart") == 1, (
        f"exactly one messageStart per message; observed order {order!r}"
    )
    assert events[0]["messageStart"]["role"] == "assistant", (
        f"the opening frame must declare the assistant role; got {events[0]!r}"
    )
    assert order.count("messageStop") == 1, (
        f"exactly one messageStop per message; observed order {order!r}"
    )
    assert order[-1] == "metadata" and order.count("metadata") == 1, (
        f"exactly one metadata frame, and it must be last; observed order {order!r}"
    )
    assert order.index("messageStop") == len(order) - 2, (
        f"messageStop must be the frame immediately before metadata; observed order {order!r}"
    )

    delta_indices = [e["contentBlockDelta"]["contentBlockIndex"]
                     for e in events if "contentBlockDelta" in e]
    stop_indices = [e["contentBlockStop"]["contentBlockIndex"]
                    for e in events if "contentBlockStop" in e]

    assert delta_indices, (
        f"a stream that carried no contentBlockDelta produced no content; observed {order!r}"
    )
    assert delta_indices[0] == 0, (
        f"contentBlockIndex must start at 0; first delta index was {delta_indices[0]} "
        f"over {delta_indices!r}"
    )
    assert delta_indices == sorted(delta_indices), (
        f"contentBlockIndex must never move backwards within a message; got {delta_indices!r}"
    )
    assert sorted(set(delta_indices)) == list(range(max(delta_indices) + 1)), (
        f"the delta indices must be a dense run from 0; got {sorted(set(delta_indices))!r}"
    )
    assert stop_indices == sorted(set(delta_indices)), (
        f"exactly one contentBlockStop per delta index, in index order; "
        f"stops={stop_indices!r} delta indices={sorted(set(delta_indices))!r}"
    )
    # A stop closes its block: no delta may carry an index that has already been stopped.
    stopped: set[int] = set()
    for event in events:
        key = _keys(event)
        if key == "contentBlockDelta":
            idx = event[key]["contentBlockIndex"]
            assert idx not in stopped, (
                f"contentBlockDelta arrived at index {idx} after that index was stopped; "
                f"observed order {order!r}"
            )
        elif key == "contentBlockStop":
            stopped.add(event[key]["contentBlockIndex"])
    assert "contentBlockDelta" not in order[order.index("messageStop"):], (
        f"no contentBlockDelta may follow messageStop; observed order {order!r}"
    )

    streamed_text = "".join(
        e["contentBlockDelta"]["delta"].get("text", "")
        for e in events if "contentBlockDelta" in e
    )
    assert "PONG" in streamed_text.upper(), (
        f"the reassembled deltas lost the token the prompt forced; got {streamed_text!r}"
    )

    metadata = events[-1]["metadata"]
    usage = metadata["usage"]
    assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"], (
        f"the metadata frame's own token arithmetic must close; usage={usage!r}"
    )
    assert usage["outputTokens"] > 0, (
        f"the metadata frame must report the tokens the stream actually produced; usage={usage!r}"
    )

    # Cross-operation reconciliation: byte-identical messages must be charged identical input
    # tokens whether the answer is streamed or not.
    unary = rt.converse(modelId=MODEL_ID, messages=messages, inferenceConfig=_INFERENCE)
    unary_text = "".join(b.get("text", "") for b in unary["output"]["message"]["content"])
    assert "PONG" in unary_text.upper(), (
        f"the non-streaming Converse lost the token the prompt forced; got {unary_text!r}"
    )
    assert unary["usage"]["inputTokens"] == usage["inputTokens"], (
        f"identical messages must be charged identical inputTokens on both operations; "
        f"stream={usage['inputTokens']} unary={unary['usage']['inputTokens']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
