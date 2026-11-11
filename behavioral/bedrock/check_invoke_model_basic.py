"""invoke-model-basic."""
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


def _invoke_model_raw(rt, user_message, *, max_tokens=256):
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": user_message}],
        }
    )
    resp = rt.invoke_model(
        modelId=MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=body.encode(),
    )
    return json.loads(resp["body"].read())

CHECK = "invoke-model-basic"
GROUP = 'invoke_model'
SERVICES = ['bedrock']

def _extract_text(resp):
    if "content" in resp and resp["content"]:
        return "".join(
            block.get("text", "") for block in resp["content"] if isinstance(block, dict)
        )
    if "choices" in resp and resp["choices"]:
        message = resp["choices"][0].get("message", {})
        return message.get("content", "") or ""
    return None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel returns a valid JSON response with the requested generated text."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = _invoke_model_raw(rt, "Say exactly: hello")
    # Model-agnostic: response must be a dict with some content
    assert isinstance(resp, dict), f"Expected dict response, got {type(resp)}"
    # Either Claude format (content[].text) or OpenAI format (choices[].message.content)
    has_content = ("content" in resp and len(resp["content"]) > 0) or (
        "choices" in resp and len(resp["choices"]) > 0
    )
    assert has_content, f"Response has no content. Keys: {list(resp.keys())}"
    text = _extract_text(resp)
    assert text, f"Could not extract generated text. Response: {resp!r}"
    assert "hello" in text.lower(), (
        f"Asked the model to say exactly 'hello', got: {text!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
