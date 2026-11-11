"""get-user-attribute-verification-code-requires-authorization."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-attribute-verification-code-requires-authorization"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUserAttributeVerificationCode with a garbage access token is rejected with
    NotAuthorizedException, while the identical call with the real token succeeds before and
    after, isolating the rejection to the bad token."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    email = f"{ctx.unique_name('verify-')}@example.com"
    _create_confirmed_user(
        ctx, pool_id, username, password, user_attributes=[{"Name": "email", "Value": email}]
    )
    access_token = _admin_password_auth(ctx, pool_id, client_id, username, password)["AccessToken"]

    resp = idp.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="email")
    assert resp["CodeDeliveryDetails"]["AttributeName"] == "email", resp

    code, message = _error(
        lambda: idp.get_user_attribute_verification_code(
            AccessToken="not-a-real-access-token", AttributeName="email"
        )
    )
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected = "Invalid Access Token"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Restore: the identical call with the real access token still succeeds,
    # proving the rejection was specific to the bad token, not a broken user/pool.
    resp_after = idp.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="email")
    assert resp_after["CodeDeliveryDetails"]["AttributeName"] == "email", resp_after


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
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
