"""execute-sampling-operation-prompt-required-rejected."""

from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-sampling-operation-prompt-required-rejected"
GROUP = "sampling-operations"
SERVICES = ["sagemakertrainingsessionruntime"]


def _client(ctx):
    return ctx.client(
        "sagemakertrainingsessionruntime",
        config=Config(use_dualstack_endpoint=True, parameter_validation=False),
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SampleConfig's required "prompt" member is enforced even when every other member of the
    sample configuration is present and otherwise well-formed."""
    runtime = _client(ctx)
    name = ctx.unique_name("sim2real-sagemaker-tsr-")

    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=name,
            operationConfig={"sample": {"numSamples": 1, "samplingParams": {"maxTokens": 512}}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        "1 validation error detected: Value at 'operationConfig.sample.prompt' failed to "
        "satisfy constraint: Member must not be null"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
