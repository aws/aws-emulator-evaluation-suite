"""verify-user-attribute-code-mismatch-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "verify-user-attribute-code-mismatch-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """VerifyUserAttribute with a wrong code fails and leaves the attribute unverified."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-behav-user-")
    password = "TestPassw0rd!1"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            # be explicit about the starting verification state instead of relying on
            # whatever default real Cognito applies when the attribute is left unset
            {"Name": "email_verified", "Value": "false"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    # confirm the attribute starts out unverified before requesting a code
    before = idp.get_user(AccessToken=access_token)
    assert _attr(before, "email_verified") == "false", "email should start unverified"

    idp.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="email")

    code, message = _error(
        lambda: idp.verify_user_attribute(
            AccessToken=access_token, AttributeName="email", Code="000000"
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    expected = "Invalid verification code provided, please try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = idp.get_user(AccessToken=access_token)
    assert _attr(after, "email_verified") == "false", "email must remain unverified after mismatched code"


def _attr(get_user_resp, name: str) -> str | None:
    for a in get_user_resp.get("UserAttributes", []):
        if a["Name"] == name:
            return a["Value"]
    return None


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a CodeMismatchException, but the call SUCCEEDED: {result!r}")


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
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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
