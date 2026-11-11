"""count-tokens-unsupported-capability-rejected-not-as-unknown-model."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "count-tokens-unsupported-capability-rejected-not-as-unknown-model"
GROUP = 'count_tokens_rejected'
SERVICES = ['bedrock-runtime']

_REAL_MODEL = "us.amazon.nova-micro-v1:0"
_ABSENT_MODEL = "sim2real.no-such-model-v9:0"
_INPUT = {"converse": {"messages": [{"role": "user", "content": [{"text": "hello world"}]}]}}


def _error(fn):
    """Return (code, message) for a ClientError; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call was expected to be refused but returned success")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CountTokens refuses an invocable model as unsupported, not as an invalid identifier.
    Converse proves the id valid; both refusals are ValidationException with distinct messages."""
    rt = ctx.client("bedrock-runtime")

    # Positive control: the identifier names a model this account can invoke.
    turn = rt.converse(
        modelId=_REAL_MODEL,
        messages=[{"role": "user", "content": [{"text": "hi"}]}],
        inferenceConfig={"maxTokens": 1},
    )
    assert turn["stopReason"] == "max_tokens", (
        f"positive control: Converse against {_REAL_MODEL!r} with maxTokens=1 returned stopReason "
        f"{turn['stopReason']!r}, so the identifier's validity is not established"
    )

    absent_code, absent_message = _error(
        lambda: rt.count_tokens(modelId=_ABSENT_MODEL, input=_INPUT)
    )
    assert absent_code == "ValidationException", (
        f"an identifier naming no model should be a ValidationException, got {absent_code!r}"
    )
    assert absent_message == "The provided model identifier is invalid.", (
        f"unexpected refusal message for an absent model: {absent_message!r}"
    )

    real_code, real_message = _error(
        lambda: rt.count_tokens(modelId=_REAL_MODEL, input=_INPUT)
    )
    assert real_code == "ValidationException", (
        f"a real model that cannot count tokens should be a ValidationException, got {real_code!r}"
    )
    assert real_message == "The provided model doesn't support counting tokens.", (
        f"{_REAL_MODEL!r} is invocable, so CountTokens must refuse it as an unsupported "
        f"capability, not as an unknown identifier; got {real_message!r}"
    )

    # The distinction is the whole point: the two refusals must not be the same envelope.
    assert absent_message != real_message, (
        f"both refusals carried the identical message {real_message!r}, so a caller cannot tell "
        f"a wrong model id from an unsupported operation"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
