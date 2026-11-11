"""empty-vs-absent-optional-field-distinguished."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-vs-absent-optional-field-distinguished"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"


def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Converse succeeds with `system` absent or non-empty but rejects an empty system text
    with ValidationException, so absence and explicit emptiness are not interchangeable."""
    bedrock = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": "Say hello."}]}]

    absent_resp = bedrock.converse(modelId=TEXT_MODEL, messages=messages, inferenceConfig={"maxTokens": 10})
    absent_text = absent_resp["output"]["message"]["content"][0]["text"].strip()
    assert absent_text != "", f"expected non-empty completion with system absent, got {absent_text!r}"

    # The text member is NonEmptyString, so botocore would reject "" client-side; disable
    # parameter validation so the assertion is on the service's own rejection.
    unvalidated = ctx.client("bedrock-runtime", config=Config(parameter_validation=False))

    def _empty_system_call():
        unvalidated.converse(
            modelId=TEXT_MODEL,
            messages=messages,
            system=[{"text": ""}],
            inferenceConfig={"maxTokens": 10},
        )

    code, message = _error(_empty_system_call)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "1 validation error detected: Value at 'system.1.member.text' failed to satisfy constraint: Member must have length greater than or equal to 1", f"unexpected refusal message {message!r}"

    # Positive control: a present, non-empty system prompt succeeds.
    nonempty_resp = bedrock.converse(
        modelId=TEXT_MODEL,
        messages=messages,
        system=[{"text": "You are a terse assistant."}],
        inferenceConfig={"maxTokens": 10},
    )
    nonempty_text = nonempty_resp["output"]["message"]["content"][0]["text"].strip()
    assert nonempty_text != "", f"expected non-empty completion with non-empty system, got {nonempty_text!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
