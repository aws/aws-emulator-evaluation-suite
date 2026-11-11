"""execute-sampling-operation-load-weights-arn-format-unchecked."""

from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-sampling-operation-load-weights-arn-format-unchecked"
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
    """loadWeightsForSampling's required modelPackageArn is enforced for absence, but its
    documented SageMaker model-package ARN format is never checked once the member is present."""
    runtime = _client(ctx)
    name = ctx.unique_name("sim2real-sagemaker-tsr-")

    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=name, operationConfig={"loadWeightsForSampling": {}}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        "1 validation error detected: Value null at "
        "'operationConfig.loadWeightsForSampling.modelPackageArn' failed to satisfy "
        "constraint: Member must not be null"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=name,
            operationConfig={"loadWeightsForSampling": {"modelPackageArn": "not-an-arn"}},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"a present but non-ARN-shaped modelPackageArn was expected to proceed to the session "
        f"lookup unvalidated, got {code}: {message!r}"
    )
    expected = f"Session not found: {name}-{ctx.account}-{ctx.region}"
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
