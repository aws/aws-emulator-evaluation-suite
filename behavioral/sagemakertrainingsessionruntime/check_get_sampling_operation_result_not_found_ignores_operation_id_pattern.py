"""get-sampling-operation-result-not-found-ignores-operation-id-pattern."""

from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sampling-operation-result-not-found-ignores-operation-id-pattern"
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
    """GetSamplingOperationResult reports the operation, not the session, as absent, and —
    unlike ExecuteSamplingOperation's trainingSessionName — never validates operationId's
    pattern: a syntactically invalid id is reported not-found rather than refused."""
    runtime = _client(ctx)
    name = ctx.unique_name("sim2real-sagemaker-tsr-")
    operation_id = ctx.unique_name("sim2real-sagemaker-tsr-op-")

    code, message = _error(
        lambda: runtime.get_sampling_operation_result(
            trainingSessionName=name, operationId=operation_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code}: {message!r}"
    )
    expected = f"Sample request not found: {operation_id}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    invalid_operation_id = "not an id!"
    code, message = _error(
        lambda: runtime.get_sampling_operation_result(
            trainingSessionName=name, operationId=invalid_operation_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"a pattern-violating operationId was expected to be reported not-found rather than "
        f"refused as a validation error, got {code}: {message!r}"
    )
    expected = f"Sample request not found: {invalid_operation_id}"
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
