"""invoke-model-content-type-header."""
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

CHECK = "invoke-model-content-type-header"
GROUP = 'invoke_model'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel response has contentType=application/json."""
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
        f"Expected contentType='application/json', got {resp.get('contentType')}"
    )
    parsed = json.loads(resp["body"].read())
    assert isinstance(parsed, dict) and len(parsed) > 0, (
        f"declared contentType='application/json' but body did not decode to a "
        f"non-empty JSON object: {parsed!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
