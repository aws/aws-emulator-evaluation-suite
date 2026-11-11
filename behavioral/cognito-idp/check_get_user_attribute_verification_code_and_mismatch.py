"""get-user-attribute-verification-code-and-mismatch."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-user-attribute-verification-code-and-mismatch"
GROUP = 'error-semantics'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUserAttributeVerificationCode for email reports delivery by EMAIL to AttributeName email;
    VerifyUserAttribute with a wrong code fails with CodeMismatchException and its exact message,
    and the rejected attempt leaves email_verified unchanged."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
        AutoVerifiedAttributes=["email"],
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    password = "Str0ngPassw0rd!"
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    before = c.get_user(AccessToken=access_token)
    before_attrs = {a["Name"]: a["Value"] for a in before["UserAttributes"]}
    before_verified = before_attrs.get("email_verified")
    assert before_verified in (None, "false"), (
        f"expected a freshly admin-created user's email to start unverified "
        f"(real Cognito omits the attribute entirely rather than reporting "
        f"'false'), got email_verified={before_verified!r} -- otherwise the "
        f"terminal 'unchanged' assertion below would hold trivially"
    )

    delivery = c.get_user_attribute_verification_code(
        AccessToken=access_token, AttributeName="email"
    )["CodeDeliveryDetails"]
    assert delivery["AttributeName"] == "email", (
        f"expected CodeDeliveryDetails.AttributeName to echo 'email', got {delivery!r}"
    )
    assert delivery["DeliveryMedium"] == "EMAIL", (
        f"expected DeliveryMedium EMAIL for the email attribute, got {delivery!r}"
    )

    code, message = _error(
        lambda: c.verify_user_attribute(
            AccessToken=access_token, AttributeName="email", Code="000000"
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    expected = "Invalid verification code provided, please try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = c.get_user(AccessToken=access_token)
    after_attrs = {a["Name"]: a["Value"] for a in after["UserAttributes"]}
    assert after_attrs.get("email_verified") == before_verified, (
        f"a rejected VerifyUserAttribute must not change email_verified: "
        f"before={before_verified!r} after={after_attrs.get('email_verified')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
