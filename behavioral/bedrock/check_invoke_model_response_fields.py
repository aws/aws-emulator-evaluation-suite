"""invoke-model-response-fields."""
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

CHECK = "invoke-model-response-fields"
GROUP = 'invoke_model'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel response has model identification and usage metrics."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    resp = _invoke_model_raw(rt, "Reply with one word.")
    assert isinstance(resp, dict), f"Expected a JSON object body, got {type(resp).__name__}: {resp!r}"
    # Must have either 'model' (Claude/OpenAI) or 'id' identifying the response
    has_id = resp.get("id") is not None or resp.get("model") is not None
    assert has_id, f"Response missing identification fields. Keys: {list(resp.keys())}"
    # Must have a usage dict reporting actual token counts (Anthropic: input_tokens/
    # output_tokens; OpenAI-compatible: prompt_tokens/completion_tokens/total_tokens) —
    # not merely a key or substring named "usage" somewhere in the body.
    usage = resp.get("usage")
    assert isinstance(usage, dict) and usage, (
        f"Response missing a usage dict. Keys: {list(resp.keys())}, usage={usage!r}"
    )
    token_counts = {k: v for k, v in usage.items() if isinstance(v, int)}
    assert token_counts, f"usage present but reports no integer token counts: {usage!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
