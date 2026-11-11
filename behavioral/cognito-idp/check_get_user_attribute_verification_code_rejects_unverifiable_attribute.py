"""get-user-attribute-verification-code-rejects-unverifiable-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-attribute-verification-code-rejects-unverifiable-attribute"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUserAttributeVerificationCode for a non-verifiable attribute (family_name) is rejected
    with InvalidParameterException, while the verifiable email attribute on the same user
    still succeeds."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    email = f"{ctx.unique_name('verify-')}@example.com"
    _create_confirmed_user(
        ctx,
        pool_id,
        username,
        password,
        user_attributes=[{"Name": "email", "Value": email}, {"Name": "family_name", "Value": "Doe"}],
    )
    access_token = _admin_password_auth(ctx, pool_id, client_id, username, password)["AccessToken"]

    code, message = _error(
        lambda: idp.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="family_name")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "Invalid attribute name. Only phone_number and email can be verified."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the verifiable "email" attribute on the same user still works.
    resp = idp.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="email")
    assert resp["CodeDeliveryDetails"]["AttributeName"] == "email", (
        f"expected CodeDeliveryDetails for email, got {resp.get('CodeDeliveryDetails')!r}"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    kwargs.setdefault("UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real"})
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-client-")
    kwargs.setdefault("ExplicitAuthFlows", ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])
    resp = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=name, GenerateSecret=False, **kwargs)
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, password, user_attributes=None):
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
        UserAttributes=user_attributes or [],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_password_auth(ctx, pool_id, client_id, username, password):
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
