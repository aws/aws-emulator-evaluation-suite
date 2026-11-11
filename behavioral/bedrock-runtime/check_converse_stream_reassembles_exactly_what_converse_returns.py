"""converse-stream-reassembles-exactly-what-converse-returns."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-stream-reassembles-exactly-what-converse-returns"
GROUP = "streaming"
SERVICES = ["bedrock-runtime"]

# Pinned rather than read from the environment: every number below is a per-model fact.
MODEL_ID = "amazon.nova-lite-v1:0"

# A mechanically checkable output, graded by shape (see _integer_run), never by the model's prose.
_PROMPT = (
    "Output the integers from 1 to 20 inclusive in ascending order, separated by single commas, "
    "with no spaces, no line breaks, no preamble and no trailing text."
)
_INFERENCE = {"maxTokens": 256, "temperature": 0.0, "topP": 1.0}
_MIN_DELTAS = 2


def _unary_text(resp) -> str:
    """Concatenate every text block of a Converse response, rejecting a non-text turn."""
    content = resp["output"]["message"]["content"]
    assert content, (
        f"the unary turn returned an empty content list, so there is nothing to compare the "
        f"stream against; output={resp['output']!r}"
    )
    non_text = [sorted(b) for b in content if "text" not in b]
    assert not non_text, (
        f"a plain-text prompt with no toolConfig must come back as text blocks only; got "
        f"non-text blocks {non_text!r}"
    )
    return "".join(b["text"] for b in content)


def _normalise(s: str) -> str:
    """Whitespace-insensitive form, reported in the equality message only."""
    return "".join(s.split())


def _integer_run(s: str) -> list[int]:
    """Parse the forced output as a comma-separated integer run, raising if it is not one."""
    parts = [p.strip() for p in s.strip().split(",")]
    bad = [p for p in parts if not p.isdigit()]
    assert not bad, (
        f"the forced prompt asked for comma-separated integers and nothing else; these fields "
        f"are not integers: {bad!r} (full text {s!r})"
    )
    return [int(p) for p in parts]


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream's text deltas (at least two, none carrying the whole completion) reassemble to
    exactly the text Converse returns, and both operations agree on stopReason and inputTokens.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html
    """
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    # The unary operation is the reference the stream is graded against.
    unary = rt.converse(modelId=MODEL_ID, messages=messages, inferenceConfig=_INFERENCE)
    assert unary["stopReason"] == "end_turn", (
        f"maxTokens={_INFERENCE['maxTokens']} is far above the forced 20-integer output, so the "
        f"unary turn must finish on its own; got stopReason={unary['stopReason']!r}"
    )
    unary_text = _unary_text(unary)
    unary_run = _integer_run(unary_text)
    assert unary_run == list(range(1, 21)), (
        f"the prompt forces the ascending run 1..20; the unary turn produced {unary_run!r} from "
        f"text {unary_text!r}. Re-word the prompt rather than weakening this assertion."
    )
    unary_usage = unary["usage"]
    assert unary_usage["totalTokens"] == unary_usage["inputTokens"] + unary_usage["outputTokens"], (
        f"TokenUsage.totalTokens is documented as the total of input and generated tokens; the "
        f"unary turn reported {unary_usage!r}"
    )

    # The event stream is a single-pass iterator.
    streamed = rt.converse_stream(
        modelId=MODEL_ID, messages=messages, inferenceConfig=_INFERENCE)
    order: list[str] = []
    text_deltas: list[str] = []
    other_deltas: list[dict] = []
    stream_stop_reason = None
    stream_usage = None
    for event in streamed["stream"]:
        assert len(event) == 1, (
            f"each ConverseStream event is one member of the ConverseStreamOutput union; got "
            f"{sorted(event)!r}"
        )
        (key,) = event
        assert key not in ("internalServerException", "modelStreamErrorException",
                           "validationException", "throttlingException",
                           "serviceUnavailableException"), (
            f"the stream carried an error event, so this run cannot grade reassembly: {event!r}"
        )
        order.append(key)
        if key == "contentBlockDelta":
            delta = event["contentBlockDelta"]["delta"]
            if "text" in delta:
                text_deltas.append(delta["text"])
            else:
                other_deltas.append(delta)
        elif key == "messageStop":
            stream_stop_reason = event["messageStop"]["stopReason"]
        elif key == "metadata":
            stream_usage = event["metadata"]["usage"]

    assert not other_deltas, (
        f"a plain-text prompt with no toolConfig must produce text deltas only; got "
        f"{other_deltas!r}"
    )
    assert order[0] == "messageStart", (
        f"the first event of a ConverseStream must be messageStart; the event order was {order!r}"
    )
    assert order[-1] == "metadata", (
        f"the metadata event carrying usage closes the stream; the event order was {order!r}"
    )
    assert order.index("messageStop") < order.index("metadata"), (
        f"messageStop must precede the metadata event; the event order was {order!r}"
    )
    assert "contentBlockStop" in order, (
        f"every opened content block must be closed by a contentBlockStop; the event order was "
        f"{order!r}"
    )
    assert order.index("contentBlockStop") > order.index("contentBlockDelta"), (
        f"contentBlockStop must follow the deltas of the block it closes; the event order was "
        f"{order!r}"
    )

    # Catches a target that buffers the whole completion and ships it in one frame.
    non_empty = [d for d in text_deltas if d]
    assert len(non_empty) >= _MIN_DELTAS, (
        f"real incremental framing must split a {len(unary_text)}-character completion into at "
        f"least {_MIN_DELTAS} non-empty text deltas; got {len(non_empty)} "
        f"delta(s) {text_deltas!r}. One buffered blob is the failure this leg exists to catch."
    )
    reassembled = "".join(text_deltas)
    hogs = [d for d in text_deltas if d.strip() == reassembled.strip()]
    assert not hogs, (
        f"no single delta may carry the entire completion, which would mean the other "
        f"{len(non_empty) - 1} non-empty frames are padding around one buffered blob; "
        f"deltas={text_deltas!r}"
    )

    # temperature=0.0/topP=1.0 makes decoding greedy, so both paths must produce the same text.
    assert reassembled.strip() == unary_text.strip(), (
        f"ConverseStream's reassembled deltas must equal Converse's text for a "
        f"temperature=0.0/topP=1.0 request; streamed={reassembled.strip()!r} "
        f"unary={unary_text.strip()!r} "
        f"(whitespace-insensitive forms equal: "
        f"{_normalise(reassembled) == _normalise(unary_text)})"
    )
    assert stream_stop_reason == unary["stopReason"], (
        f"the two operations must agree on why generation stopped; streamed "
        f"{stream_stop_reason!r} unary {unary['stopReason']!r}"
    )
    assert stream_usage is not None, (
        f"ConverseStream must close with a metadata event carrying usage; the event order was "
        f"{order!r}"
    )
    assert (stream_usage["totalTokens"]
            == stream_usage["inputTokens"] + stream_usage["outputTokens"]), (
        f"the streamed metadata usage must satisfy the same totalTokens arithmetic as the unary "
        f"response; got {stream_usage!r}"
    )
    assert stream_usage["inputTokens"] == unary_usage["inputTokens"], (
        f"input tokenisation depends only on the request, so an identical request must be charged "
        f"identical inputTokens on both operations; streamed={stream_usage['inputTokens']} "
        f"unary={unary_usage['inputTokens']} (full usage streamed={stream_usage!r} "
        f"unary={unary_usage!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
