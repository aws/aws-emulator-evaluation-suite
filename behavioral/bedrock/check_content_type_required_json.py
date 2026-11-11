"""content-type-required-json."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

MODEL_ID = "moonshotai.kimi-k2.5"

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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

CHECK = "content-type-required-json"
GROUP = 'content_types'
SERVICES = ['bedrock']

@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel without application/json contentType gets ValidationException; the
    identical call with the correct contentType succeeds, so the rejection is attributable to
    the header and not to a blanket denial of InvokeModel for this model."""
    rt = ctx.client("bedrock-runtime")
    _require_model_access(rt)
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "hi"}],
        }
    ).encode()

    # Positive control: the same call shape, correct contentType.
    resp = rt.invoke_model(modelId=MODEL_ID, contentType="application/json", body=body)
    assert resp.get("contentType") == "application/json", (
        f"the positive control (correct contentType) did not succeed as expected: "
        f"{resp.get('contentType')!r}"
    )

    code, message = _error(
        lambda: rt.invoke_model(
            modelId=MODEL_ID,
            contentType="text/plain",
            body=body)
    )
    assert code == "ValidationException", (
        f"Expected ValidationException for text/plain contentType, got {code!r}"
    )
    expected_message = "The provided Content Type is invalid or not supported for this model"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
