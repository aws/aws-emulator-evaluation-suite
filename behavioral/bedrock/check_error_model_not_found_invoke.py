"""error-model-not-found-invoke."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("expected invoke_model to raise, it succeeded")


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

CHECK = "error-model-not-found-invoke"
GROUP = 'errors'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel with a non-existent model ID is rejected, on an account otherwise able to invoke."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}],
        }
    )
    got = _error(
        lambda: rt.invoke_model(
            modelId="anthropic.claude-nonexistent-model-v99",
            contentType="application/json",
            body=body.encode())
    )
    # Measured on real AWS: an unrecognized modelId is rejected at request validation,
    # never reaching a resource lookup, regardless of whether the id is well-formed.
    expected = ("ValidationException", "The provided model identifier is invalid.")
    assert got == expected, f"Expected {expected!r} for a non-existent model id, got {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
