"""record-handler-progress-transitions."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "record-handler-progress-transitions"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RecordHandlerProgress with an externally supplied BearerToken, reporting SUCCESS or FAILED, fails with
    ValidationError "BearerToken '<token>' is invalid" before any state check, while DescribeAccountLimits
    reports a positive StackLimit."""
    cfn = ctx.client("cloudformation")

    limits = cfn.describe_account_limits()["AccountLimits"]
    limits_by_name = {limit["Name"]: limit["Value"] for limit in limits}
    assert limits_by_name.get("StackLimit", 0) > 0, (
        f"expected a positive StackLimit from a healthy CloudFormation control "
        f"plane, got {limits_by_name}"
    )

    bogus_token = str(uuid.uuid4())
    code, message = _error_code(
        lambda: cfn.record_handler_progress(
            BearerToken=bogus_token,
            OperationStatus="SUCCESS",
            StatusMessage="sim2real behavioral probe",
        )
    )
    assert code == "ValidationError", (
        f"expected ValidationError for an unknown BearerToken, got {code}"
    )
    expected = f"BearerToken '{bogus_token}' is invalid"
    assert message == expected, (
        f"expected the ValidationError to name this BearerToken: {expected!r}, got {message!r}"
    )

    # an invalid state transition (jumping straight to a terminal status with no
    # matching in-flight record) is rejected the same way regardless of the reported status
    code_failed, message_failed = _error_code(
        lambda: cfn.record_handler_progress(
            BearerToken=bogus_token,
            OperationStatus="FAILED",
            ErrorCode="InternalFailure",
            StatusMessage="sim2real behavioral probe",
        )
    )
    assert code_failed == "ValidationError", (
        f"expected ValidationError for an unknown BearerToken, got {code_failed}"
    )
    expected_failed = f"BearerToken '{bogus_token}' is invalid"
    assert message_failed == expected_failed, (
        f"expected the ValidationError to name this BearerToken: {expected_failed!r}, got {message_failed!r}"
    )


def _code_and_message(exc) -> tuple[str | None, str | None]:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error", {})
        return error.get("Code"), error.get("Message")
    return None, None


def _error_code(fn) -> tuple[str | None, str | None]:
    """Call fn(); return (code, message) of the error it raises. An unexpected success raises,
    so an emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        return _code_and_message(exc)
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
