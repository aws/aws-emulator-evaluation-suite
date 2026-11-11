"""change-password-wrong-old-password-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-password-wrong-old-password-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ChangePassword with an incorrect current password fails and leaves the password unchanged."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-behav-user-")
    correct_password = "CorrectPassw0rd!1"
    attempted_new_password = "AttemptedPassw0rd!2"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        MessageAction="SUPPRESS",
        TemporaryPassword=correct_password,
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=correct_password, Permanent=True
    )

    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": correct_password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    code, code_msg = _error_code(
        lambda: idp.change_password(
            PreviousPassword="TotallyWrongPassw0rd!9",
            ProposedPassword=attempted_new_password,
            AccessToken=access_token,
        )
    )
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    assert code_msg == 'Incorrect username or password.', f"expected the exact {code} message, got {code_msg!r}"

    # password must remain unchanged: the CORRECT password should still authenticate
    reauth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": correct_password},
    )
    assert "AuthenticationResult" in reauth, "correct password no longer authenticates after failed ChangePassword"


def _error_code(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
        UserPoolTags=_POOL_TAGS,
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
        GenerateSecret=False,
    )["UserPoolClient"]
    return client["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
