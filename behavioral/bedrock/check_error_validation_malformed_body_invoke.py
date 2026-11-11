"""error-validation-malformed-body-invoke."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected InvokeModel to raise, but it succeeded with {result!r}")


def _invoke_model_well_formed(rt):
    """Positive control: the same operation, the same model, a body it actually accepts —
    so a target that rejects every InvokeModel call cannot pass this as 'the malformed body
    was rejected'."""
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}],
        }
    )
    try:
        resp = rt.invoke_model(
            modelId=MODEL_ID,
            contentType="application/json",
            body=body.encode())
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "") or type(exc).__name__
        raise AssertionError(
            f"positive control failed: well-formed InvokeModel for {MODEL_ID} raised {code}"
        ) from exc
    payload = json.loads(resp["body"].read())
    assert isinstance(payload, dict) and payload, (
        f"positive control: expected a non-empty JSON response body, got {payload!r}"
    )

CHECK = "error-validation-malformed-body-invoke"
GROUP = 'errors'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel with non-JSON body returns ValidationException, though the same model
    accepts a well-formed one."""
    rt = ctx.client("bedrock-runtime")
    _invoke_model_well_formed(rt)
    code, message = _error(
        lambda: rt.invoke_model(
            modelId=MODEL_ID,
            contentType="application/json",
            body=b"this is not json{{{")
    )
    assert code == "ValidationException", (
        f"Expected ValidationException for malformed body, got {code!r}"
    )
    expected = (
        "The JSON object in the request body is malformed. "
        "Fix the syntax errors and retry your request."
    )
    assert message == expected, f"Expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
