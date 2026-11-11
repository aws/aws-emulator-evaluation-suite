"""execute-sampling-then-get-result-session-not-found-consistent."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-sampling-then-get-result-session-not-found-consistent"
GROUP = "lifecycle"
SERVICES = ["sagemakertrainingsessionruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Submitting a sampling operation against a never-created training session fails closed
    with ResourceNotFoundException, and polling that session for any operation id afterwards
    fails closed the same way, never materializing an operation record for it.
    """
    client = ctx.client("sagemakertrainingsessionruntime")
    session_name = ctx.unique_name("sim2real-stsr-sess-")

    def _execute():
        return client.execute_sampling_operation(
            trainingSessionName=session_name,
            operationConfig={
                "sample": {
                    "prompt": {"chunks": [{"tokens": [1, 2, 3], "type": "encoded_text"}]},
                    "numSamples": 1,
                    "samplingParams": {"maxTokens": 512},
                }
            },
        )

    execute_code, execute_message = _error_code(_execute)
    assert execute_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {execute_code}"
    )
    expected_execute = f"Session not found: {session_name}-{ctx.account}-{ctx.region}"
    assert execute_message == expected_execute, (
        f"expected message {expected_execute!r}, got {execute_message!r}"
    )

    fabricated_operation_id = ctx.unique_name("sim2real-stsr-op-")

    def _poll():
        return client.get_sampling_operation_result(
            trainingSessionName=session_name, operationId=fabricated_operation_id
        )

    poll_code, poll_message = _error_code(_poll)
    assert poll_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {poll_code}"
    )
    expected_poll = f"Sample request not found: {fabricated_operation_id}"
    assert poll_message == expected_poll, (
        f"expected message {expected_poll!r}, got {poll_message!r}"
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
