"""execute-sampling-vs-stream-same-malformed-session-diverge."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-sampling-vs-stream-same-malformed-session-diverge"
GROUP = "validation-asymmetry"
SERVICES = ["sagemakertrainingsessionruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteSamplingOperation pattern-validates trainingSessionName before any session lookup;
    SampleTrainingSessionWithResponseStream does not, so the identical malformed name answers
    ValidationException on one surface and ResourceNotFoundException on the other.
    """
    client = ctx.client("sagemakertrainingsessionruntime")
    malformed_session = "bad name!"

    def _execute():
        return client.execute_sampling_operation(
            trainingSessionName=malformed_session,
            operationConfig=_sample_config(),
        )

    execute_code, execute_message = _error_code(_execute)
    assert execute_code == "ValidationException", (
        f"expected ValidationException, got {execute_code}"
    )
    expected_execute = (
        f"1 validation error detected: Value '{malformed_session}' at 'trainingSessionName' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-zA-Z0-9-]+"
    )
    assert execute_message == expected_execute, (
        f"expected message {expected_execute!r}, got {execute_message!r}"
    )

    def _stream():
        return client.sample_training_session_with_response_stream(
            trainingSessionName=malformed_session,
            contentType="application/json",
            accept="application/json",
            body=b"{}",
        )

    stream_code, stream_message = _error_code(_stream)
    assert stream_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {stream_code}"
    )
    expected_stream = f"Session not found: {malformed_session}-{ctx.account}-{ctx.region}"
    assert stream_message == expected_stream, (
        f"expected message {expected_stream!r}, got {stream_message!r}"
    )


def _sample_config() -> dict:
    return {
        "sample": {
            "prompt": {"chunks": [{"tokens": [1, 2, 3], "type": "encoded_text"}]},
            "numSamples": 1,
            "samplingParams": {"maxTokens": 512},
        }
    }


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
