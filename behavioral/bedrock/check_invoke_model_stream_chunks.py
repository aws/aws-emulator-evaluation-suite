"""invoke-model-stream-chunks."""
from __future__ import annotations

import json

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

CHECK = "invoke-model-stream-chunks"
GROUP = 'invoke_stream'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModelWithResponseStream returns chunked response events."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 50,
            "messages": [{"role": "user", "content": "Say hello."}],
        }
    )
    resp = rt.invoke_model_with_response_stream(
        modelId=MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=body.encode())
    chunks: list[dict] = []
    text_parts: list[str] = []
    stop_reasons: list[str] = []
    for event in resp["body"]:
        chunk = event.get("chunk")
        if chunk:
            data = json.loads(chunk["bytes"].decode())
            chunks.append(data)
            # Model-agnostic: OpenAI-style chat.completion.chunk or Anthropic-native event.
            if "choices" in data:
                choice = data["choices"][0]
                text_parts.append(choice.get("delta", {}).get("content") or "")
                if choice.get("finish_reason"):
                    stop_reasons.append(choice["finish_reason"])
            elif data.get("type") == "content_block_delta":
                text_parts.append(data.get("delta", {}).get("text") or "")
            elif data.get("type") == "message_delta":
                stop_reason = data.get("delta", {}).get("stop_reason")
                if stop_reason:
                    stop_reasons.append(stop_reason)
    assert len(chunks) > 0, "No chunks received from InvokeModelWithResponseStream"
    full_text = "".join(text_parts)
    assert len(full_text) >= 2, f"Reconstructed streamed text too short: {full_text!r}"
    assert stop_reasons, f"No chunk reported a stop/finish reason; stream did not terminate cleanly ({chunks!r})"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
