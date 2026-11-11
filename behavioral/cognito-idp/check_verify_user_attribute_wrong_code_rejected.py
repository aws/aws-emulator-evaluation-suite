"""verify-user-attribute-wrong-code-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "verify-user-attribute-wrong-code-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """VerifyUserAttribute rejects a code that doesn't match the one Cognito sent,
    leaving the attribute unverified."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Str0ng!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "false"},
        ],
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    access_token = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    idp.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="email")

    code, message = _error(
        lambda: idp.verify_user_attribute(AccessToken=access_token, AttributeName="email", Code="000000")
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    expected = "Invalid verification code provided, please try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    attrs = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert attrs["email_verified"] == "false", (
        f"rejected VerifyUserAttribute must not verify the attribute, got email_verified={attrs['email_verified']!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a target
    that accepts a wrong verification code is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"VerifyUserAttribute with a wrong code SUCCEEDED, returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
