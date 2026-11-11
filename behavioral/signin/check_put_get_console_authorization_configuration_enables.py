"""put-get-console-authorization-configuration-enables."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-get-console-authorization-configuration-enables"
GROUP = "console-authorization"
SERVICES = ["signin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:signin-console-authorization")
def run(ctx) -> None:
    """PutConsoleAuthorizationConfiguration for the caller's own account answers that targetId, scope ACCOUNT
    and enabled=true, and a subsequent Get reads back the same three values.
    """
    signin = _east_client(ctx)
    account_id = _account_id(ctx)
    # Put is not idempotent (a second Put on an already-enabled target is
    # ConflictException) -- clear any pre-existing configuration first so
    # this check works whether the account starts fresh or already enabled.
    _delete_if_exists(signin, account_id)
    ctx.on_cleanup(lambda: signin.delete_console_authorization_configuration(targetId=account_id))

    put_resp = signin.put_console_authorization_configuration(targetId=account_id)
    assert put_resp["targetId"] == account_id, (
        f"expected Put to echo targetId={account_id!r}, got {put_resp['targetId']!r}"
    )
    assert put_resp["scope"] == "ACCOUNT", (
        f"expected Put to auto-detect scope='ACCOUNT' for an account-id target, got {put_resp['scope']!r}"
    )
    assert put_resp["consoleAuthorizationEnabled"] is True, (
        f"expected Put to report consoleAuthorizationEnabled=True, got {put_resp['consoleAuthorizationEnabled']!r}"
    )

    get_resp = signin.get_console_authorization_configuration(targetId=account_id)
    assert get_resp["targetId"] == account_id, (
        f"expected Get to echo targetId={account_id!r}, got {get_resp['targetId']!r}"
    )
    assert get_resp["scope"] == "ACCOUNT", (
        f"expected Get to reflect scope='ACCOUNT', got {get_resp['scope']!r}"
    )
    assert get_resp["consoleAuthorizationEnabled"] is True, (
        f"expected Get to reflect consoleAuthorizationEnabled=True after Put, got {get_resp['consoleAuthorizationEnabled']!r}"
    )


def _east_client(ctx):
    """Console-authorization WRITE ops are region-locked to us-east-1 (Put/Delete raise
    ValidationException 'Write operations only supported in us-east' from any other region)."""
    return ctx.client("signin", region="us-east-1")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _delete_if_exists(signin, target_id: str) -> None:
    try:
        signin.delete_console_authorization_configuration(targetId=target_id)
    except ClientError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
