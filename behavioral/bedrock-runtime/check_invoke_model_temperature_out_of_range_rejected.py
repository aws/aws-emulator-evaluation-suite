"""invoke-model-temperature-out-of-range-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-model-temperature-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeModel on Nova with inferenceConfig.temperature above 1.0 is refused with
    ValidationException and the exact range message, while an in-range temperature on the same model
    and prompt returns text.
    """
    brt = ctx.client("bedrock-runtime")

    out_of_range_body = json.dumps(
        {
            "messages": [{"role": "user", "content": [{"text": "Say hello."}]}],
            "inferenceConfig": {"temperature": 5.0, "maxTokens": 8},
        }
    )
    code, message = _error(
        lambda: brt.invoke_model(modelId=MODEL_ID, body=out_of_range_body, contentType="application/json")
    )
    assert code == "ValidationException", code
    assert message == 'Malformed input request: the provided temperature must be between 0.0 and 1.0, please reformat your input and try again.', f"unexpected refusal message {message!r}"

    in_range_body = json.dumps(
        {
            "messages": [{"role": "user", "content": [{"text": "Say hello."}]}],
            "inferenceConfig": {"temperature": 0.5, "maxTokens": 8},
        }
    )
    control = brt.invoke_model(modelId=MODEL_ID, body=in_range_body, contentType="application/json")
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
