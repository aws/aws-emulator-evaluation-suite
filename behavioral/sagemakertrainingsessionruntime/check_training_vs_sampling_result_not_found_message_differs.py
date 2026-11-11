"""training-vs-sampling-result-not-found-message-differs."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "training-vs-sampling-result-not-found-message-differs"
GROUP = "sibling-surface"
SERVICES = ["sagemakertrainingsessionruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTrainingOperationResult and GetSamplingOperationResult both answer
    ResourceNotFoundException for the same never-created operationId, but with distinct wording,
    so the two lookups are separate code paths rather than one delegating to the other.
    """
    client = ctx.client("sagemakertrainingsessionruntime")
    session_name = ctx.unique_name("sim2real-stsr-sess-")
    operation_id = ctx.unique_name("sim2real-stsr-op-")

    def _get_training():
        return client.get_training_operation_result(
            trainingSessionName=session_name, operationId=operation_id
        )

    training_code, training_message = _error_code(_get_training)
    assert training_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {training_code}"
    )
    expected_training = f"Operation not found: {operation_id}"
    assert training_message == expected_training, (
        f"expected message {expected_training!r}, got {training_message!r}"
    )

    def _get_sampling():
        return client.get_sampling_operation_result(
            trainingSessionName=session_name, operationId=operation_id
        )

    sampling_code, sampling_message = _error_code(_get_sampling)
    assert sampling_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {sampling_code}"
    )
    expected_sampling = f"Sample request not found: {operation_id}"
    assert sampling_message == expected_sampling, (
        f"expected message {expected_sampling!r}, got {sampling_message!r}"
    )

    assert training_message != sampling_message, (
        f"the two sibling lookups must word a not-found differently, both gave {training_message!r}"
    )


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected success raises: accepting
    input that AWS rejects is a difference worth surfacing."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
