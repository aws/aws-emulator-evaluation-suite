"""update-user-attributes-verification-code-mismatch-fails."""
from __future__ import annotations

# The real verification code cannot be captured: the CustomMessage_UpdateUserAttribute trigger
# receives the literal placeholder "{####}" as request.codeParameter, so only the wrong-code
# boundary is asserted.

from behavioral_harness import tags

CHECK = "update-user-attributes-verification-code-mismatch-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUserAttributes on a pending-verification attribute sends a code (echoed for the right
    attribute and medium); confirming it with a wrong code fails CodeMismatchException and leaves
    the attribute unverified."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-behav-user-")
    password = "TestPassw0rd!1"
    original_email = f"{username}-orig@example.com"
    new_email = f"{username}-new@example.com"

    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": original_email},
            {"Name": "email_verified", "Value": "true"},
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

    update_resp = idp.update_user_attributes(
        AccessToken=access_token, UserAttributes=[{"Name": "email", "Value": new_email}]
    )
    delivery_list = update_resp.get("CodeDeliveryDetailsList") or []
    assert delivery_list, "expected verification code to be sent for email change"
    assert delivery_list[0]["AttributeName"] == "email", delivery_list[0]
    assert delivery_list[0]["DeliveryMedium"] in ("EMAIL", "SMS"), delivery_list[0]

    pending = idp.get_user(AccessToken=access_token)
    assert _attr(pending, "email_verified") == "false", "changing email should reset verified flag to false"

    code, message = _error(
        lambda: idp.verify_user_attribute(
            AccessToken=access_token, AttributeName="email", Code="000000"
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException, got {code}"
    assert message == "Invalid verification code provided, please try again.", message

    after = idp.get_user(AccessToken=access_token)
    assert _attr(after, "email_verified") == "false", "email must remain unverified after mismatched code"
    assert _attr(after, "email") == new_email, "the pending email itself must be unaffected by a rejected code"


# ===== helpers =====
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
        # UpdateUserAttributes only triggers a verification-code send for an attribute
        # change when that attribute is one of the pool's AutoVerifiedAttributes; without
        # this, real Cognito just updates the email silently with no CodeDeliveryDetailsList.
        AutoVerifiedAttributes=["email"],
        # Real Cognito defaults a freshly created pool to DeletionProtection=ACTIVE,
        # which makes DeleteUserPool fail; ctx.on_cleanup swallows that failure, so an
        # unset DeletionProtection here leaks the pool on every run, pass or fail.
        DeletionProtection="INACTIVE",
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
