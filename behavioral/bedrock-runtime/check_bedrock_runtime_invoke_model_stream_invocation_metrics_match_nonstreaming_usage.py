"""bedrock-runtime-invoke-model-stream-invocation-metrics-match-nonstreaming-usage."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "bedrock-runtime-invoke-model-stream-invocation-metrics-match-nonstreaming-usage"
GROUP = 'streaming'
SERVICES = ['bedrock-runtime']

# The native request body is model-specific, so the model id is pinned with it.
MODEL_ID = "amazon.nova-lite-v1:0"

#: The native (non-Converse) request body, sent byte-identically on both operations.
_BODY = json.dumps({
    "messages": [{"role": "user",
                  "content": [{"text": "Reply with exactly the single word PONG and nothing "
                                       "else."}]}],
    "inferenceConfig": {"maxTokens": 64, "temperature": 0.0},
}, sort_keys=True)
_METRICS_KEY = "amazon-bedrock-invocationMetrics"


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The native response stream ends with one invocationMetrics chunk matching InvokeModel usage.

    A byte-identical body must be charged the same input tokens on both operations.
    """
    rt = ctx.client("bedrock-runtime")

    # Streamed first. botocore already decodes the base64 'bytes' member, so each event's payload
    # is raw JSON. The stream is single-pass: iterate exactly once.
    streamed = rt.invoke_model_with_response_stream(
        modelId=MODEL_ID, body=_BODY,
        contentType="application/json", accept="application/json")
    decoded = []
    for event in streamed["body"]:
        assert "chunk" in event, (
            f"every event on the native response stream must carry a 'chunk'; got keys "
            f"{sorted(event)!r}"
        )
        decoded.append(json.loads(event["chunk"]["bytes"]))

    assert decoded, "the native response stream yielded no chunks at all"
    assert all(isinstance(o, dict) for o in decoded), (
        f"every chunk's bytes must decode to one JSON object; got types "
        f"{[type(o).__name__ for o in decoded]!r}"
    )
    assert sum(1 for o in decoded if _METRICS_KEY in o) == 1, (
        f"{_METRICS_KEY} must appear exactly once; it appeared "
        f"{sum(1 for o in decoded if _METRICS_KEY in o)} times over keys "
        f"{[sorted(o) for o in decoded]!r}"
    )
    assert _METRICS_KEY in decoded[-1], (
        f"the invocation metrics belong to the LAST chunk of the stream; the last three chunks "
        f"carried keys {[sorted(o) for o in decoded[-3:]]!r}"
    )

    # Unlike ConverseStream, each native delta opens its own contentBlockIndex and is closed
    # by its own contentBlockStop.
    delta_indices = [o["contentBlockDelta"]["contentBlockIndex"]
                     for o in decoded if "contentBlockDelta" in o]
    stop_indices = [o["contentBlockStop"]["contentBlockIndex"]
                    for o in decoded if "contentBlockStop" in o]
    assert delta_indices, (
        f"the stream carried no contentBlockDelta, so it produced no text; chunk keys "
        f"{[sorted(o) for o in decoded]!r}"
    )
    assert delta_indices == sorted(delta_indices) and delta_indices[0] == 0, (
        f"contentBlockIndex must start at 0 and never move backwards; got {delta_indices!r}"
    )
    assert stop_indices == sorted(set(delta_indices)), (
        f"every content block opened by a delta must be closed by exactly one contentBlockStop; "
        f"stops={stop_indices!r} delta indices={sorted(set(delta_indices))!r}"
    )

    streamed_text = "".join(o["contentBlockDelta"]["delta"].get("text", "")
                            for o in decoded if "contentBlockDelta" in o)
    assert "PONG" in streamed_text.upper(), (
        f"the reassembled native stream lost the token the prompt forced; got {streamed_text!r}"
    )

    metrics = decoded[-1][_METRICS_KEY]
    stream_usage = decoded[-1]["metadata"]["usage"]
    assert metrics["inputTokenCount"] > 0 and metrics["outputTokenCount"] > 0, (
        f"the metrics chunk must report the tokens the invocation actually used; got {metrics!r}"
    )
    assert metrics["invocationLatency"] > 0, (
        f"the metrics chunk must report a positive end-to-end latency; got {metrics!r}"
    )
    assert metrics["firstByteLatency"] > 0, (
        f"the metrics chunk must report a positive time-to-first-byte, which is the whole reason "
        f"a caller streams; got {metrics!r}"
    )
    assert metrics["outputTokenCount"] == stream_usage["outputTokens"], (
        f"the metrics chunk and the metadata chunk of the SAME invocation must agree on the "
        f"output tokens; metrics={metrics!r} metadata usage={stream_usage!r}"
    )

    # The unary native call over the byte-identical body.
    unary = json.loads(rt.invoke_model(
        modelId=MODEL_ID, body=_BODY,
        contentType="application/json", accept="application/json")["body"].read())
    unary_text = "".join(b.get("text", "")
                         for b in unary["output"]["message"]["content"])
    assert "PONG" in unary_text.upper(), (
        f"the unary native invocation lost the token the prompt forced; got {unary_text!r}"
    )
    assert metrics["inputTokenCount"] == unary["usage"]["inputTokens"], (
        f"a byte-identical body must be charged identical input tokens on both operations; "
        f"streamed inputTokenCount={metrics['inputTokenCount']} unary "
        f"inputTokens={unary['usage']['inputTokens']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
