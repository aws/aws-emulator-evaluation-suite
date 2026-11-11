"""tool-use-converse."""
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

CHECK = "tool-use-converse"
GROUP = 'e2e_workflows'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse with toolConfig triggers a toolUse content block in the response."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    tool_config = {
        "tools": [
            {
                "toolSpec": {
                    "name": "get_weather",
                    "description": "Get current weather for a location",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "location": {
                                    "type": "string",
                                    "description": "City name",
                                }
                            },
                            "required": ["location"],
                        }
                    },
                }
            }
        ],
        "toolChoice": {"any": {}},
    }
    resp = rt.converse(
        modelId=MODEL_ID,
        messages=[
            {"role": "user", "content": [{"text": "What's the weather in Paris?"}]},
        ],
        toolConfig=tool_config,
        # 200 was too tight for this model: it can spend most of the budget on internal
        # reasoning before ever emitting the toolUse block, so the call hits max_tokens with
        # an empty content list (observed on real Bedrock) -- not a declined tool call.
        inferenceConfig={"maxTokens": 500})
    # The response should contain a toolUse content block
    content = resp["output"]["message"]["content"]
    tool_use_blocks = [b for b in content if "toolUse" in b]
    assert len(tool_use_blocks) > 0, (
        f"Expected at least one toolUse block in response. "
        f"Content block types: {[list(b.keys()) for b in content]}"
    )
    tool_use = tool_use_blocks[0]["toolUse"]
    assert tool_use["name"] == "get_weather", (
        f"Expected tool name 'get_weather', got {tool_use['name']!r}"
    )
    assert tool_use.get("input", {}).get("location"), (
        f"toolUse input must carry a non-empty 'location' extracted from the prompt; "
        f"got {tool_use.get('input')!r}"
    )
    # toolChoice forces tool use, so a toolUse block always terminates the turn as
    # stopReason='tool_use' -- never 'end_turn' -- confirmed against real Bedrock.
    assert resp["stopReason"] == "tool_use", (
        f"Expected stopReason='tool_use', got {resp['stopReason']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
