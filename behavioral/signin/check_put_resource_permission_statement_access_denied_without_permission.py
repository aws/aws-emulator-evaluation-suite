"""put-resource-permission-statement-access-denied-without-permission."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-permission-statement-access-denied-without-permission"
GROUP = "overly-permissive"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePermissionStatement is rejected with AccessDeniedException and the exact message and creates
    no statement, while ListResourcePermissionStatements for the same caller is not denied, so the refusal is
    specific to this action.
    """
    signin = ctx.client("signin")
    caller_arn = _caller_arn(ctx)

    try:
        signin.list_resource_permission_statements(maxResults=25)
        control_code = None
    except ClientError as err:
        control_code = err.response["Error"]["Code"]
    assert control_code != "AccessDeniedException", (
        f"expected the caller's ListResourcePermissionStatements call (same resource, a "
        f"different action) to clear IAM authorization, got AccessDeniedException -- so the "
        f"PutResourcePermissionStatement denial below cannot be shown to be action-specific"
    )

    code, message = _error_code_and_message(
        lambda: signin.put_resource_permission_statement(excludedPrincipal=caller_arn)
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller without "
        f"signin:PutResourcePermissionStatement, got {code!r} ({message!r})"
    )
    assert message == "No Access to PutResourcePermissionStatement API", (
        f"expected the exact denial 'No Access to PutResourcePermissionStatement API', got {message!r}"
    )

    # effect absent: the denied call must not have created a statement. With no resource-based
    # policy, List raises ResourceNotFoundException, which is itself the confirmation; only a
    # populated page naming the caller would indicate a leak.
    try:
        stmts = signin.list_resource_permission_statements(maxResults=100).get(
            "permissionStatements", []
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException or a page without our marker, got {err.response['Error']!r}"
        )
        assert err.response["Error"].get("Message") == "Requested resource not found", (
            f"expected message 'Requested resource not found', got {err.response['Error'].get('Message')!r}"
        )
    else:
        assert not any(_contains_value(s, caller_arn) for s in stmts)


def _caller_arn(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Arn"]


def _contains_value(obj, target: str) -> bool:
    if isinstance(obj, str):
        return target in obj
    if isinstance(obj, dict):
        return any(_contains_value(v, target) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_contains_value(v, target) for v in obj)
    return False


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
