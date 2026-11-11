"""malformed-request-body-not-forwarded-to-model."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-request-body-not-forwarded-to-model"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A structurally invalid JSON body given to InvokeModel is rejected at the API boundary
    with ValidationException -- it is never forwarded to the model backend for processing --
    while a well-formed body for the same model succeeds normally (positive control)."""
    bedrock = ctx.client("bedrock-runtime")

    # Positive control: a well-formed JSON body is accepted and produces real output.
    good_body = json.dumps(
        {"messages": [{"role": "user", "content": [{"text": "Say hello."}]}], "inferenceConfig": {"maxTokens": 20, "temperature": 0, "topP": 1}}
    ).encode("utf-8")
    good_resp = bedrock.invoke_model(modelId=TEXT_MODEL, body=good_body, contentType="application/json")
    good_out = json.loads(good_resp["body"].read())
    good_text = good_out["output"]["message"]["content"][0]["text"]
    assert good_text.strip() != "", f"well-formed InvokeModel call returned empty text: {good_out!r}"

    # A structurally malformed (not-even-valid-JSON) body must be rejected outright.
    malformed_body = b'{"messages": [{"role": "user", "content": [{maxTokenCount: 20,,,}'

    def _malformed_call():
        bedrock.invoke_model(modelId=TEXT_MODEL, body=malformed_body, contentType="application/json")

    code, message = _error_code(_malformed_call)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "Malformed input request, please reformat your input and try again.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
