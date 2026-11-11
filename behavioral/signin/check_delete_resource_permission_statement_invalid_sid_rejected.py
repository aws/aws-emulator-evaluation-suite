"""delete-resource-permission-statement-invalid-sid-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-permission-statement-invalid-sid-rejected"
GROUP = "overly-permissive"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePermissionStatement rejects a statementId outside ^[A-Za-z0-9+/]{64}=?$ with
    ValidationException and the exact message, while a well-formed but nonexistent sid passes shape
    validation and is refused with the exact AccessDeniedException.
    """
    signin = ctx.client("signin")

    malformed_sid = "not-a-valid-sid!!"
    malformed_code, malformed_message = _error(
        lambda: signin.delete_resource_permission_statement(statementId=malformed_sid)
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a malformed sid, got {malformed_code!r}"
    )
    expected_malformed = (
        f"1 validation error detected: Value '{malformed_sid}' at 'statementId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [A-Za-z0-9+/]{64}=?"
    )
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r} for a malformed sid, got {malformed_message!r}"
    )

    wellformed_nonexistent_sid = "A" * 64
    notfound_code, notfound_message = _error(
        lambda: signin.delete_resource_permission_statement(statementId=wellformed_nonexistent_sid)
    )
    # This account has no signin:DeleteResourcePermissionStatement permission at all, so the
    # permission check fires before the existence check: AccessDeniedException, not
    # ResourceNotFoundException.
    assert notfound_code == "AccessDeniedException", (
        f"expected AccessDeniedException (permission checked before existence) for a "
        f"shape-valid but nonexistent sid, got {notfound_code!r}"
    )
    expected_denied = "No Access to DeleteResourcePermissionStatement API"
    assert notfound_message == expected_denied, (
        f"expected message {expected_denied!r} for a shape-valid but nonexistent sid, got {notfound_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
