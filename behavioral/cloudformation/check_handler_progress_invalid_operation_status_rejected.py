"""handler-progress-invalid-operation-status-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "handler-progress-invalid-operation-status-rejected"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RecordHandlerProgress with OperationStatus or CurrentOperationStatus "BOGUS_STATUS" fails with
    ValidationError and the exact "failed to satisfy constraint: Member must satisfy enum value set"
    message naming the field; botocore does not validate enums, so the service answers both."""
    cfn = ctx.client("cloudformation")

    token = str(uuid.uuid4())
    error = _client_error(
        lambda: cfn.record_handler_progress(BearerToken=token, OperationStatus="BOGUS_STATUS")
    )
    assert error.get("Code") == "ValidationError", (
        f"expected ValidationError for an out-of-enum OperationStatus, got {error!r}"
    )
    expected_message = (
        "1 validation error detected: Value 'BOGUS_STATUS' at 'operationStatus' failed to satisfy "
        "constraint: Member must satisfy enum value set: "
        "[CANCEL_IN_PROGRESS, SUCCESS, IN_PROGRESS, PENDING, FAILED, CANCEL_COMPLETE]"
    )
    assert error.get("Message") == expected_message, f"expected message {expected_message!r}, got {error!r}"

    other_token = str(uuid.uuid4())
    error_2 = _client_error(
        lambda: cfn.record_handler_progress(
            BearerToken=other_token,
            OperationStatus="SUCCESS",
            CurrentOperationStatus="BOGUS_STATUS",
        )
    )
    assert error_2.get("Code") == "ValidationError", (
        f"expected ValidationError for an out-of-enum CurrentOperationStatus, got {error_2!r}"
    )
    expected_message_2 = (
        "1 validation error detected: Value 'BOGUS_STATUS' at 'currentOperationStatus' failed to "
        "satisfy constraint: Member must satisfy enum value set: "
        "[CANCEL_IN_PROGRESS, SUCCESS, IN_PROGRESS, PENDING, FAILED, CANCEL_COMPLETE]"
    )
    assert error_2.get("Message") == expected_message_2, (
        f"expected message {expected_message_2!r}, got {error_2!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"RecordHandlerProgress accepted a malformed request and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
