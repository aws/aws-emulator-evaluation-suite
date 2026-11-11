"""count-tokens-rejects-unsupported-model-not-blanket-failure."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "count-tokens-rejects-unsupported-model-not-blanket-failure"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

# An invokable model that CountTokens does not support.
MODEL_ID = "amazon.nova-lite-v1:0"
TEXT_MESSAGE = "Describe, in one paragraph, why the sky appears blue during the day."
EXPECTED_MESSAGE = "The provided model doesn't support counting tokens."


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CountTokens refuses a model it cannot count with a specific ValidationException, while
    Converse on the same modelId succeeds, so the refusal is not an access or availability issue."""
    brt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": TEXT_MESSAGE}]}]

    # Positive control: rules out account access or model availability as the cause.
    control = brt.converse(modelId=MODEL_ID, messages=messages, inferenceConfig={"maxTokens": 16})
    assert control["usage"]["inputTokens"] > 0, (
        f"positive control: Converse against {MODEL_ID!r} reported no inputTokens usage, "
        f"got {control['usage']!r}"
    )

    code, message = _error_code_and_message(
        lambda: brt.count_tokens(modelId=MODEL_ID, input={"converse": {"messages": messages}})
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == EXPECTED_MESSAGE, f"expected {EXPECTED_MESSAGE!r}, got {message!r}"


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        "count_tokens against a model CountTokens does not support was expected to be "
        "refused but returned success"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
