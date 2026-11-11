"""handler-progress-bearer-token-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "handler-progress-bearer-token-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RecordHandlerProgress with a random bearer token, reporting IN_PROGRESS or SUCCESS, fails with
    ValidationError "BearerToken '<token>' is invalid": only tokens CloudFormation issues to an in-flight
    extension handler are accepted."""
    cfn = ctx.client("cloudformation")

    fake_bearer_token = str(uuid.uuid4())
    error = _client_error(
        lambda: cfn.record_handler_progress(BearerToken=fake_bearer_token, OperationStatus="IN_PROGRESS")
    )
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    expected_message = f"BearerToken '{fake_bearer_token}' is invalid"
    assert error.get("Message") == expected_message, f"expected message {expected_message!r}, got {error!r}"

    # A second, differently-shaped fabricated invocation (claiming terminal SUCCESS
    # directly) must be rejected the same way -- the bearer-token/shape validation
    # happens before any state-transition business logic.
    other_fake_token = str(uuid.uuid4())
    error_2 = _client_error(
        lambda: cfn.record_handler_progress(
            BearerToken=other_fake_token,
            OperationStatus="SUCCESS",
            StatusMessage="sim2real behavioral probe",
        )
    )
    assert error_2.get("Code") == "ValidationError", f"expected ValidationError, got {error_2!r}"
    expected_message_2 = f"BearerToken '{other_fake_token}' is invalid"
    assert error_2.get("Message") == expected_message_2, (
        f"expected message {expected_message_2!r}, got {error_2!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
