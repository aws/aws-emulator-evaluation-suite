"""bedrock-converse-stream-emits-its-events-in-the-declared-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bedrock-converse-stream-emits-its-events-in-the-declared-order"
GROUP = 'converse_stream'
SERVICES = ['bedrock']

# Pinned: the text leg compares two temperature-0 generations of this one model.
MODEL_ID = "amazon.nova-lite-v1:0"

_PROMPT = "Reply with exactly the single word: pineapple"

# The event grammar, with the variable-length delta run collapsed to one entry.
_EXPECTED = ["messageStart", "contentBlockDelta", "contentBlockStop", "messageStop", "metadata"]


def _collapse(keys):
    """Adjacent duplicates folded, so a 2-delta and a 40-delta stream compare equal."""
    out = []
    for k in keys:
        if not out or out[-1] != k:
            out.append(k)
    return out


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3", "cap:c6")
def run(ctx) -> None:
    """ConverseStream events follow messageStart, deltas, contentBlockStop, messageStop, metadata
    with no delta after messageStop, and the deltas rebuild the non-streaming Converse answer.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ConverseStream.html
    """
    rt = ctx.client("bedrock-runtime")

    streamed = rt.converse_stream(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig={"maxTokens": 30, "temperature": 0.0},
    )

    keys, delta_text, metadata = [], "", None
    for event in streamed["stream"]:
        for key in event:
            keys.append(key)
            if key == "contentBlockDelta":
                delta_text += event[key]["delta"].get("text", "")
            elif key == "metadata":
                metadata = event[key]

    assert keys[0] == "messageStart", (
        f"the stream must open with 'messageStart'; observed sequence {keys!r}"
    )
    assert keys[-1] == "metadata", (
        f"the stream must close with 'metadata'; observed sequence {keys!r}"
    )
    assert _collapse(keys) == _EXPECTED, (
        f"the event grammar (delta run collapsed) must be {_EXPECTED!r}; "
        f"observed {_collapse(keys)!r} from the full sequence {keys!r}"
    )
    assert keys.count("contentBlockDelta") >= 1, (
        f"a stream that carried no contentBlockDelta produced no text; observed {keys!r}"
    )
    stop_at = keys.index("messageStop")
    assert "contentBlockDelta" not in keys[stop_at:], (
        f"no contentBlockDelta may follow 'messageStop'; observed {keys!r}"
    )

    assert metadata is not None, f"no metadata event in the stream; observed {keys!r}"
    assert metadata["usage"]["outputTokens"] > 0, (
        f"the metadata event must report the tokens the stream actually produced; "
        f"metadata={metadata!r}"
    )

    # The streamed text must reconstruct the non-streaming answer for the identical request, or,
    # since AWS documents no determinism at temperature 0, both must carry the prompted word.
    nonstreamed = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig={"maxTokens": 30, "temperature": 0.0},
    )
    nonstreamed_text = "".join(
        b.get("text", "") for b in nonstreamed["output"]["message"]["content"]
    )
    assert delta_text.strip(), (
        f"the concatenated deltas must be non-empty; observed sequence {keys!r}"
    )
    assert delta_text.strip() == nonstreamed_text.strip() or (
        "pineapple" in delta_text.lower() and "pineapple" in nonstreamed_text.lower()
    ), (
        f"the streamed text must equal the non-streamed answer for the same temperature-0 "
        f"request or both must answer the prompt; streamed={delta_text!r} "
        f"non-streamed={nonstreamed_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
