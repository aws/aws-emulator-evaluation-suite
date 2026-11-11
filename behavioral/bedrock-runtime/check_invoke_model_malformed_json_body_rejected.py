"""invoke-model-malformed-json-body-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-model-malformed-json-body-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel rejects a body that is not valid JSON for the target model with
    ValidationException, and never returns a synthesized 200 response for it; the identical
    call with a well-formed native Nova body still succeeds (positive control)."""
    brt = ctx.client("bedrock-runtime")

    code, message = _error(
        lambda: brt.invoke_model(
            modelId=MODEL_ID, body=b"this is not json at all {{{", contentType="application/json"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == 'Malformed input request, please reformat your input and try again.', f"unexpected refusal message {message!r}"

    valid_body = json.dumps(
        {
            "messages": [{"role": "user", "content": [{"text": "Say hello in one word."}]}],
            "inferenceConfig": {"temperature": 0, "maxTokens": 8},
        }
    )
    control = brt.invoke_model(modelId=MODEL_ID, body=valid_body, contentType="application/json")
    payload = json.loads(control["body"].read())
    content = payload["output"]["message"]["content"]
    assert any("text" in block and block["text"] for block in content), content


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
