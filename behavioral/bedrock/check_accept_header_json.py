"""accept-header-json."""
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

CHECK = "accept-header-json"
GROUP = 'content_types'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel with accept=application/json succeeds and returns valid JSON."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "hi"}],
        }
    )
    resp = rt.invoke_model(
        modelId=MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=body.encode())
    assert resp.get("contentType") == "application/json", (
        f"Expected response contentType='application/json' for accept='application/json', "
        f"got {resp.get('contentType')!r}"
    )
    parsed = json.loads(resp["body"].read())
    assert isinstance(parsed, dict), f"Response is not a JSON object: {type(parsed)}"
    has_content = ("content" in parsed and len(parsed["content"]) > 0) or (
        "choices" in parsed and len(parsed["choices"]) > 0
    )
    assert has_content, f"Response has no model content. Keys: {list(parsed.keys())}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
