"""bedrock-tool-use-round-trip-returns-the-tool-result-in-the-final-answer."""
from __future__ import annotations

import random

from behavioral_harness import tags

CHECK = "bedrock-tool-use-round-trip-returns-the-tool-result-in-the-final-answer"
GROUP = 'converse'
SERVICES = ['bedrock']

# Pinned: tool-use behaviour differs per model.
MODEL_ID = "amazon.nova-lite-v1:0"

_SYMBOL = "ZZQX"
_TOOL_NAME = "get_stock_price"
_QUESTION = (
    f"What is the current share price of {_SYMBOL}? Use the {_TOOL_NAME} tool, then report "
    f"the price_usd value exactly as the tool returned it."
)

_TOOL_CONFIG = {
    "tools": [{
        "toolSpec": {
            "name": _TOOL_NAME,
            "description": "Get the current share price in USD for a ticker symbol.",
            "inputSchema": {"json": {
                "type": "object",
                "properties": {"symbol": {"type": "string",
                                          "description": "The ticker symbol."}},
                "required": ["symbol"],
            }},
        }
    }]
}


def _text(resp):
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """The model calls the tool, then repeats the tool's nonce price, absent from turn 1, in turn 2,
    proving the value travelled through the toolResult rather than being guessed.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/tool-use.html
    """
    rt = ctx.client("bedrock-runtime")

    # An unguessable but plausible decimal: an odd-looking price makes the model comment on the
    # format instead of reporting it.
    price = f"{random.randint(300, 899)}.{random.randint(10, 99)}"
    user_turn = {"role": "user", "content": [{"text": _QUESTION}]}

    first = rt.converse(
        modelId=MODEL_ID,
        toolConfig=_TOOL_CONFIG,
        messages=[user_turn],
        inferenceConfig={"maxTokens": 500, "temperature": 0.0},
    )
    assert first["stopReason"] == "tool_use", (
        f"the model must stop to call the tool; got {first['stopReason']!r} with content "
        f"{first['output']['message']['content']!r}"
    )
    tool_uses = [b["toolUse"] for b in first["output"]["message"]["content"] if "toolUse" in b]
    assert len(tool_uses) == 1, (
        f"exactly one toolUse block expected; got {len(tool_uses)} from content "
        f"{first['output']['message']['content']!r}"
    )
    tool_use = tool_uses[0]
    assert tool_use["name"] == _TOOL_NAME, (
        f"the toolUse must name the declared tool {_TOOL_NAME!r}; got {tool_use!r}"
    )
    assert tool_use["input"] == {"symbol": _SYMBOL}, (
        f"the toolUse input must carry the symbol from the prompt -- an emulator returning an "
        f"empty input dict fails here; got {tool_use['input']!r}"
    )
    assert tool_use.get("toolUseId"), (
        f"the service must mint a toolUseId for the second turn to reference; got {tool_use!r}"
    )
    assert price not in _text(first), (
        f"the price must not appear before the tool returned it, otherwise turn 2 proves "
        f"nothing; price={price!r} turn-1 text={_text(first)!r}"
    )

    second = rt.converse(
        modelId=MODEL_ID,
        toolConfig=_TOOL_CONFIG,
        messages=[
            user_turn,
            first["output"]["message"],
            {"role": "user", "content": [{"toolResult": {
                "toolUseId": tool_use["toolUseId"],
                "content": [{"json": {"symbol": _SYMBOL, "price_usd": price}}],
                "status": "success",
            }}]},
        ],
        inferenceConfig={"maxTokens": 400, "temperature": 0.0},
    )
    second_text = _text(second)
    assert price in second_text, (
        f"the value returned through the toolResult must reach the final answer verbatim; "
        f"price={price!r} answer={second_text!r}"
    )
    assert second["stopReason"] == "end_turn", (
        f"having consumed the toolResult the model must finish rather than call again; got "
        f"{second['stopReason']!r} answer={second_text!r}"
    )
    assert second["usage"]["outputTokens"] > 0, (
        f"the second turn must be a real generation; usage={second['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
