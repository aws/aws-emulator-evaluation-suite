"""converse-stream-invalid-model-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "converse-stream-invalid-model-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-runtime"]


@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ConverseStream against a modelId that does not exist is rejected with ValidationException
    (Bedrock resolves model identifiers against its static catalog at request-validation time,
    before streaming begins)."""
    br = ctx.client("bedrock-runtime")

    # positive control: a valid model streams successfully
    control = br.converse_stream(
        modelId="amazon.nova-lite-v1:0",
        messages=[{"role": "user", "content": [{"text": "Say the word 'hello'."}]}],
        inferenceConfig={"maxTokens": 32},
    )
    control_events = list(control["stream"])
    assert any("messageStop" in event for event in control_events), (
        f"control call against a valid model must complete its stream; got events "
        f"{control_events!r}"
    )

    # break exactly one thing: a syntactically valid but nonexistent model id
    bogus_model_id = "amazon.titan-text-does-not-exist-v99"

    code, message = _error(
        lambda: list(
            br.converse_stream(
                modelId=bogus_model_id,
                messages=[{"role": "user", "content": [{"text": "hello"}]}],
            )["stream"]
        )
    )
    assert code == "ValidationException", (
        f"ConverseStream against nonexistent model {bogus_model_id!r} returned code {code!r}, "
        f"expected ValidationException"
    )
    assert message == 'The provided model identifier is invalid.', f"unexpected refusal message {message!r}"

    # effect absent: the bogus model id still doesn't exist on a second attempt
    code_again, message_again = _error(
        lambda: list(
            br.converse_stream(
                modelId=bogus_model_id,
                messages=[{"role": "user", "content": [{"text": "hello"}]}],
            )["stream"]
        )
    )
    assert code_again == "ValidationException", (
        f"a repeated ConverseStream against the same nonexistent model {bogus_model_id!r} "
        f"returned code {code_again!r}, expected ValidationException again"
    )
    assert message_again == message, f"the repeated refusal changed its message: {message_again!r}"

    # the valid model is unaffected and still serves the same in-file positive control
    control_2 = br.converse_stream(
        modelId="amazon.nova-lite-v1:0",
        messages=[{"role": "user", "content": [{"text": "Say the word 'hello'."}]}],
        inferenceConfig={"maxTokens": 32},
    )
    control_2_events = list(control_2["stream"])
    assert any("messageStop" in event for event in control_2_events), (
        f"control call against a valid model must complete its stream after the rejection; "
        f"got events {control_2_events!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a model id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
