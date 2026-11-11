"""converse-tool-use-full-cycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-tool-use-full-cycle"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"

TOOL_CONFIG = {
    "tools": [
        {
            "toolSpec": {
                "name": "get_weather",
                "description": "Get the current weather for a named location.",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {"location": {"type": "string"}},
                        "required": ["location"],
                    }
                },
            }
        }
    ],
    "toolChoice": {"any": {}},
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse returns tool_use, takes a toolResult, then ends the turn with an answer using it.
    The toolResult temperature is a fixed value never in the prompt, so seeing it in the final
    answer proves the tool result propagated."""
    brt = ctx.client("bedrock-runtime")

    # Positive and two-digit: a negative value risks the model paraphrasing it ("minus 5"), and a
    # single digit can occur in unrelated text by chance; a fixed value makes every run identical.
    temp_c = 37

    messages = [
        {
            "role": "user",
            "content": [{"text": "What is the weather in Paris? You must use the get_weather tool."}],
        }
    ]
    first = brt.converse(
        modelId=MODEL_ID,
        messages=messages,
        toolConfig=TOOL_CONFIG,
        inferenceConfig={"maxTokens": 128, "temperature": 0},
    )
    assert first["stopReason"] == "tool_use", (
        f"expected stopReason 'tool_use' with toolChoice=any; got {first['stopReason']!r} "
        f"content={first['output']['message']['content']!r}"
    )

    tool_use_blocks = [b["toolUse"] for b in first["output"]["message"]["content"] if "toolUse" in b]
    assert len(tool_use_blocks) == 1, (
        f"expected exactly one toolUse block; got {first['output']['message']['content']!r}"
    )
    tool_use = tool_use_blocks[0]
    assert tool_use["name"] == "get_weather", f"expected tool 'get_weather'; got {tool_use['name']!r}"
    assert "location" in tool_use["input"], f"expected a 'location' argument; got {tool_use['input']!r}"
    assert "paris" in tool_use["input"]["location"].lower(), (
        f"expected the location extracted from the prompt to be Paris; "
        f"got {tool_use['input']['location']!r}"
    )
    assert str(temp_c) not in "".join(
        b.get("text", "") for b in first["output"]["message"]["content"]
    ), f"the temperature must not appear before the tool returns it; temp_c={temp_c}"

    messages.append(first["output"]["message"])
    messages.append(
        {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": tool_use["toolUseId"],
                        "content": [{"text": f"Sunny, {temp_c} degrees Celsius."}],
                        "status": "success",
                    }
                }
            ],
        }
    )

    # toolChoice falls back to the default "auto" so a model holding its tool result ends the turn.
    followup_tool_config = {"tools": TOOL_CONFIG["tools"]}
    final = brt.converse(
        modelId=MODEL_ID,
        messages=messages,
        toolConfig=followup_tool_config,
        inferenceConfig={"maxTokens": 128, "temperature": 0},
    )
    assert final["stopReason"] == "end_turn", (
        f"expected stopReason 'end_turn' once the tool result is supplied; "
        f"got {final['stopReason']!r} content={final['output']['message']['content']!r}"
    )
    final_text = "".join(b["text"] for b in final["output"]["message"]["content"] if "text" in b)
    assert str(temp_c) in final_text, (
        f"the temperature supplied through the toolResult ({temp_c}) must reach the final "
        f"answer, proving the tool result actually propagated; answer={final_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
