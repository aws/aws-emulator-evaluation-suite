"""get-endpoints-skip-session-name-pattern-validation."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-endpoints-skip-session-name-pattern-validation"
GROUP = "validation-asymmetry"
SERVICES = ["sagemakertrainingsessionruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTrainingOperationResult and GetSamplingOperationResult key their lookup on operationId
    alone, so a trainingSessionName outside the modelled pattern still reaches
    ResourceNotFoundException on both, unlike ExecuteSamplingOperation's ValidationException.
    """
    client = ctx.client("sagemakertrainingsessionruntime")
    malformed_session = "bad name!"
    operation_id = ctx.unique_name("sim2real-stsr-op-")

    def _get_training():
        return client.get_training_operation_result(
            trainingSessionName=malformed_session, operationId=operation_id
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
            trainingSessionName=malformed_session, operationId=operation_id
        )

    sampling_code, sampling_message = _error_code(_get_sampling)
    assert sampling_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {sampling_code}"
    )
    expected_sampling = f"Sample request not found: {operation_id}"
    assert sampling_message == expected_sampling, (
        f"expected message {expected_sampling!r}, got {sampling_message!r}"
    )

    def _execute():
        return client.execute_sampling_operation(
            trainingSessionName=malformed_session,
            operationConfig={
                "sample": {
                    "prompt": {"chunks": [{"tokens": [1, 2, 3], "type": "encoded_text"}]},
                    "numSamples": 1,
                    "samplingParams": {"maxTokens": 512},
                }
            },
        )

    execute_code, _ = _error_code(_execute)
    assert execute_code == "ValidationException", (
        f"the same malformed trainingSessionName must still be caught by ExecuteSamplingOperation's "
        f"pattern check, proving the two Get* calls above did not pass it merely because the "
        f"service stopped enforcing the pattern altogether; got {execute_code}"
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
