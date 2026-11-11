"""bedrock-runtime-converse-stream-tool-use-input-arrives-only-in-deltas."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "bedrock-runtime-converse-stream-tool-use-input-arrives-only-in-deltas"
GROUP = 'streaming'
SERVICES = ['bedrock-runtime']

# Pinned: tool-use behaviour and toolChoice support differ per model.
MODEL_ID = "amazon.nova-lite-v1:0"

_TOOL_NAME = "file_ticket"
_CITY = "Reykjavik"

# Deliberately long, so the arguments span several fragments a client must accumulate.
_REPORT = (
    "The northbound elevator in the Reykjavik office stalls between floors two and three "
    "roughly every third trip, the doors then reopen after about twenty seconds, the "
    "emergency intercom crackles but does not connect, and the maintenance sticker inside "
    "the car expired in March, so please dispatch an inspector this week and also replace "
    "the flickering ceiling panel that has been buzzing since the last building inspection."
)

_TOOL_CONFIG = {
    "tools": [{"toolSpec": {
        "name": _TOOL_NAME,
        "description": "File a support ticket with a full verbatim description.",
        "inputSchema": {"json": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "description": "The city the reporter is in."},
                "description": {"type": "string",
                                "description": "The COMPLETE verbatim report text."},
            },
            "required": ["city", "description"],
        }},
    }}],
    # Forced, so the frame grammar is deterministic: with a free choice this model first emits a
    # <thinking> text block and the tool block lands at index 1, which would make the assertions
    # below depend on a preamble the model may or may not produce.
    "toolChoice": {"tool": {"name": _TOOL_NAME}},
}

_PROMPT = (f"File a support ticket using the {_TOOL_NAME} tool. The reporter is in {_CITY}. "
           f"Pass this report VERBATIM as the description, copying every word exactly: {_REPORT}")
_INFERENCE = {"maxTokens": 900, "temperature": 0.0}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A streamed tool call names itself once in contentBlockStart and carries its arguments only
    as raw JSON text in deltas, which reassemble to the same arguments Converse returns parsed.
    """
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    resp = rt.converse_stream(modelId=MODEL_ID, toolConfig=_TOOL_CONFIG, messages=messages,
                              inferenceConfig=_INFERENCE)
    events = list(resp["stream"])

    stops = [e["messageStop"]["stopReason"] for e in events if "messageStop" in e]
    assert stops == ["tool_use"], (
        f"a mandatory toolChoice must produce exactly one messageStop with stopReason "
        f"'tool_use'; got {stops!r} over frames {[list(e)[0] for e in events]!r}"
    )

    starts = [e["contentBlockStart"] for e in events if "contentBlockStart" in e]
    assert len(starts) == 1, (
        f"exactly one contentBlockStart, announcing the tool call; got {starts!r}"
    )
    start = starts[0]
    tool_start = start["start"]["toolUse"]
    assert tool_start["name"] == _TOOL_NAME, (
        f"the opening frame must name the declared tool {_TOOL_NAME!r}; got {start!r}"
    )
    assert tool_start.get("toolUseId"), (
        f"the service must mint a toolUseId in the opening frame, since nothing later carries "
        f"one; got {start!r}"
    )
    assert "input" not in tool_start, (
        f"the opening frame announces the call and must NOT carry its arguments; got {start!r}"
    )
    block = start["contentBlockIndex"]

    fragments = [e["contentBlockDelta"]["delta"]["toolUse"]["input"]
                 for e in events
                 if "contentBlockDelta" in e
                 and "toolUse" in e["contentBlockDelta"]["delta"]]
    assert fragments, (
        f"the tool-use block produced no input fragments at all; frames were "
        f"{[list(e)[0] for e in events]!r}"
    )
    assert all(isinstance(f, str) for f in fragments), (
        f"tool arguments stream as raw JSON TEXT, not as decoded objects; got types "
        f"{[type(f).__name__ for f in fragments]!r}"
    )
    assert all("toolUseId" not in f and f'"name"' not in f for f in fragments), (
        f"the argument fragments must carry only the input JSON -- identity belongs to the "
        f"opening frame alone; got {fragments!r}"
    )
    frag_blocks = {e["contentBlockDelta"]["contentBlockIndex"]
                   for e in events
                   if "contentBlockDelta" in e
                   and "toolUse" in e["contentBlockDelta"]["delta"]}
    assert frag_blocks == {block}, (
        f"every argument fragment must belong to the block the contentBlockStart opened "
        f"(index {block}); got {sorted(frag_blocks)!r}"
    )
    stopped = [e["contentBlockStop"]["contentBlockIndex"] for e in events
               if "contentBlockStop" in e]
    assert stopped == [block], (
        f"the tool-use block must be closed by exactly one contentBlockStop for index {block}; "
        f"got {stopped!r}"
    )

    joined = "".join(fragments)
    parsed = json.loads(joined)
    assert isinstance(parsed, dict), (
        f"the concatenated fragments must parse to one JSON object; got {joined!r}"
    )
    assert set(parsed) == {"city", "description"}, (
        f"the reassembled arguments must be exactly the schema's two properties; got "
        f"{sorted(parsed)!r} from {joined!r}"
    )
    assert _CITY.lower() in parsed["city"].lower(), (
        f"the tool argument lost the city the prompt supplied; got {parsed['city']!r}"
    )
    assert len(parsed["description"]) > 300, (
        f"the long argument was truncated in reassembly, so the fragments were not accumulated "
        f"in full; got {len(parsed['description'])} characters: {parsed['description']!r}"
    )

    # Cross-operation agreement: the non-streaming operation returns the SAME arguments already
    # parsed, so a streaming path that drops or reorders a fragment diverges here.
    unary = rt.converse(modelId=MODEL_ID, toolConfig=_TOOL_CONFIG, messages=messages,
                        inferenceConfig=_INFERENCE)
    unary_uses = [b["toolUse"] for b in unary["output"]["message"]["content"] if "toolUse" in b]
    assert len(unary_uses) == 1, (
        f"the non-streaming counterpart must produce exactly one toolUse block; got "
        f"{unary['output']['message']['content']!r}"
    )
    assert unary_uses[0]["name"] == _TOOL_NAME, (
        f"the non-streaming counterpart named a different tool; got {unary_uses[0]!r}"
    )
    assert set(unary_uses[0]["input"]) == set(parsed), (
        f"the streamed reassembly and the non-streamed parse must agree on which arguments were "
        f"supplied; streamed {sorted(parsed)!r} unary {sorted(unary_uses[0]['input'])!r}"
    )
    assert unary_uses[0]["input"]["city"] == parsed["city"], (
        f"the two operations disagree on the city argument for the identical request; "
        f"streamed {parsed['city']!r} unary {unary_uses[0]['input']['city']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
