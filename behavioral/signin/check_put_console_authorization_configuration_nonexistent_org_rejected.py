"""put-console-authorization-configuration-nonexistent-org-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-console-authorization-configuration-nonexistent-org-rejected"
GROUP = "overly-permissive"
SERVICES = ["signin"]

FOREIGN_ORG_MESSAGE = "Caller is not authorized for this organization"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:signin-console-authorization")
def run(ctx) -> None:
    """PutConsoleAuthorizationConfiguration and Get for a well-formed but foreign organization id fail with
    AccessDeniedException and the exact message, while a Put for the caller's own account succeeds and reads
    back enabled.
    """
    signin = _east_client(ctx)
    bogus_org_id = "o-00000000zz"

    code, message = _error(lambda: signin.put_console_authorization_configuration(targetId=bogus_org_id))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a foreign/nonexistent org, got code={code!r}"
    )
    assert message == FOREIGN_ORG_MESSAGE, (
        f"expected message {FOREIGN_ORG_MESSAGE!r} putting a foreign/nonexistent org, got {message!r}"
    )

    # effect absent: no configuration was created for the bogus org
    get_code, get_message = _error(lambda: signin.get_console_authorization_configuration(targetId=bogus_org_id))
    assert get_code == "AccessDeniedException", (
        f"expected AccessDeniedException reading the bogus org's configuration, got code={get_code!r}"
    )
    assert get_message == FOREIGN_ORG_MESSAGE, (
        f"expected message {FOREIGN_ORG_MESSAGE!r} reading the bogus org's configuration, got {get_message!r}"
    )

    # positive control: the caller's own account id is a valid target
    account_id = _account_id(ctx)
    ctx.on_cleanup(lambda: signin.delete_console_authorization_configuration(targetId=account_id))
    put_resp = signin.put_console_authorization_configuration(targetId=account_id)
    assert put_resp["consoleAuthorizationEnabled"] is True

    # independent terminal read: the enable is visible through a different operation
    get_resp = signin.get_console_authorization_configuration(targetId=account_id)
    assert get_resp["consoleAuthorizationEnabled"] is True, (
        f"expected the real account to read back enabled, got {get_resp!r}"
    )


def _east_client(ctx):
    """Console-authorization WRITE ops are region-locked to us-east-1 (Put/Delete raise
    ValidationException 'Write operations only supported in us-east' from any other region)."""
    return ctx.client("signin", region="us-east-1")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


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
