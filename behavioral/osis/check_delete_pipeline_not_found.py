"""delete-pipeline-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-pipeline-not-found"
GROUP = "error-semantics"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePipeline on a valid but never-created PipelineName fails with ResourceNotFoundException and the
    message "The pipeline <name> could not be deleted because it does not exist", while a name that breaks the
    naming pattern fails with ValidationException and its own message.
    """
    osis = ctx.client("osis")
    missing_name = ctx.unique_name("sim2real-behav-")

    error = _client_error(lambda: osis.delete_pipeline(PipelineName=missing_name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error.get('Code')!r}"
    )
    expected = f"The pipeline {missing_name} could not be deleted because it does not exist"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    # PipelineName pattern is ^[a-z][a-z0-9\-]+$ (com.amazonaws.osis#PipelineName); a
    # leading uppercase letter is within the 3-28 length bound so the request reaches
    # the service rather than being rejected client-side by botocore's param validator.
    malformed_name = "Sim2Real-Behav-Invalid"
    malformed = _client_error(lambda: osis.delete_pipeline(PipelineName=malformed_name))
    assert malformed.get("Code") == "ValidationException", (
        f"expected ValidationException for a pattern-invalid PipelineName, got {malformed.get('Code')!r}"
    )
    expected_malformed = (
        f"1 validation error detected: Value '{malformed_name}' at 'pipelineName' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9-]{2,27}"
    )
    assert malformed.get("Message") == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises rather than returning
    a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
