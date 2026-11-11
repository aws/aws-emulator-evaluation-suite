"""model-runtime-failure-mapped-to-model-error-exception."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "model-runtime-failure-mapped-to-model-error-exception"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c3", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A forced tool call with maxTokens=1 fails as ModelErrorException on Converse and as
    modelStreamErrorException on ConverseStream, never a generic validation error."""
    client = ctx.client("bedrock-runtime")
    model_id = _pick_tool_capable_model(client)
    messages = [{"role": "user", "content": [{"text": "What tool should I use right now?"}]}]
    # Schema-valid, but maxTokens is too small for a valid tool-use turn, so the model
    # itself fails it rather than Bedrock's request validator.
    tool_config = {
        "tools": [
            {
                "toolSpec": {
                    "name": "get_time",
                    "description": "Get the current time.",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "timezone": {
                                    "type": "string",
                                    "description": "IANA timezone name, e.g. 'America/New_York'",
                                }
                            },
                            "required": ["timezone"],
                        }
                    },
                }
            }
        ],
        "toolChoice": {"tool": {"name": "get_time"}},
    }
    truncated_inference_config = {"maxTokens": 1}

    sync_code, sync_message = _error_code(
        lambda: client.converse(
            modelId=model_id,
            messages=messages,
            toolConfig=tool_config,
            inferenceConfig=truncated_inference_config,
        )
    )
    assert sync_code == "ModelErrorException", f"Converse returned {sync_code!r}"
    assert sync_message == _TOOL_USE_FAILURE_MESSAGE, sync_message

    stream_code, stream_message = _error_code(
        lambda: client.converse_stream(
            modelId=model_id,
            messages=messages,
            toolConfig=tool_config,
            inferenceConfig=truncated_inference_config,
        )
    )
    # ConverseStreamOutput has no modelErrorException member; botocore surfaces the
    # event-stream error under its member name.
    assert stream_code == "modelStreamErrorException", f"code={stream_code}"
    assert stream_message == _TOOL_USE_FAILURE_MESSAGE, stream_message

    # Positive control: the identical tool config with a normal token budget succeeds.
    control = client.converse(
        modelId=model_id, messages=messages, toolConfig=tool_config, inferenceConfig={"maxTokens": 512}
    )
    assert "output" in control and "message" in control["output"], f"control response missing output.message: {control!r}"



_TOOL_USE_FAILURE_MESSAGE = (
    "Model produced invalid sequence as part of ToolUse. "
    "Please refer to the model tool use troubleshooting guide."
)

_TOOL_MODEL_CANDIDATES = [
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
    "anthropic.claude-3-5-haiku-20241022-v1:0",
]


def _pick_tool_capable_model(client) -> str:
    from botocore.exceptions import ClientError

    last_exc = None
    probe_tools = {
        "tools": [
            {
                "toolSpec": {
                    "name": "get_time",
                    "description": "Get the current time.",
                    "inputSchema": {"json": {"type": "object", "properties": {}}},
                }
            }
        ],
        "toolChoice": {"tool": {"name": "get_time"}},
    }
    for model_id in _TOOL_MODEL_CANDIDATES:
        try:
            client.converse(
                modelId=model_id,
                messages=[{"role": "user", "content": [{"text": "What tool should I use right now?"}]}],
                toolConfig=probe_tools,
            )
            return model_id
        except ClientError as exc:
            last_exc = exc
            continue
    raise AssertionError(
        f"no candidate model supports tool use via Converse in this account/region; last error: {last_exc}"
    )


def _error_code(fn):
    """Return (code, message) of the refusal, draining an event stream; RAISE on success."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
        if isinstance(result, dict) and "stream" in result:
            for _ in result["stream"]:
                pass
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

