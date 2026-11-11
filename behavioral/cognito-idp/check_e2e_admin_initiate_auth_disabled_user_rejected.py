"""e2e-admin-initiate-auth-disabled-user-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-admin-initiate-auth-disabled-user-rejected"
GROUP = "e2e"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminDisableUser really blocks sign-in: AdminInitiateAuth for a disabled user is
    rejected with NotAuthorizedException, no tokens are issued, and the same user can
    sign in again once re-enabled.
    """
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags=_POOL_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_pool(cognito, pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real123"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    def _login():
        return cognito.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )

    # Positive control: the enabled user can sign in and gets real tokens.
    control = _login()
    assert control["AuthenticationResult"]["AccessToken"], (
        f"expected the enabled user's positive-control login to return an AccessToken, got {control}"
    )

    cognito.admin_disable_user(UserPoolId=pool_id, Username=username)
    disabled = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"]
    assert disabled is False, f"expected Enabled=False after AdminDisableUser, got {disabled}"

    code, message = _error(_login)
    assert code == "NotAuthorizedException", (
        f"expected AdminInitiateAuth for a disabled user to be rejected with "
        f"NotAuthorizedException, got {code}"
    )
    assert message == "User is disabled.", (
        f"expected the exact NotAuthorizedException message 'User is disabled.', got {message!r}"
    )

    # Effect absent: re-enabling restores the ability to sign in, proving the block was
    # solely the Enabled=false state and not some unrelated breakage.
    cognito.admin_enable_user(UserPoolId=pool_id, Username=username)
    enabled = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["Enabled"]
    assert enabled is True, f"expected Enabled=True after AdminEnableUser, got {enabled}"

    restored = _login()
    assert restored["AuthenticationResult"]["AccessToken"], (
        f"expected the original password to work again once re-enabled, got {restored}"
    )


def _safe_delete_pool(cognito, pool_id: str) -> None:
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except cognito.exceptions.ResourceNotFoundException:
        pass


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the disabled user's login to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
