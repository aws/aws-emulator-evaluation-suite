"""list-resource-permission-statements-baseline-empty-shape."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-permission-statements-baseline-empty-shape"
GROUP = "resource-policy"
SERVICES = ["signin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListResourcePermissionStatements on an account with no AWS Sign-In resource-based policy raises
    ResourceNotFoundException "Requested resource not found" rather than returning an empty page.
    """
    signin = ctx.client("signin")

    code, message = _error(lambda: signin.list_resource_permission_statements(maxResults=25))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException with no permission statements, got {code!r}"
    )
    assert message == "Requested resource not found", (
        f"expected message 'Requested resource not found' with no permission statements, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
