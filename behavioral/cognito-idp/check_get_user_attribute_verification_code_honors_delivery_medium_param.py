"""get-user-attribute-verification-code-honors-delivery-medium-param."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-attribute-verification-code-honors-delivery-medium-param"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetUserAttributeVerificationCode delivers the code through the channel tied to the
    requested attribute (email -> EMAIL), and reports that exact attribute/medium/destination."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_password_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    email = f"{ctx.unique_name('sim2real-verify-')}@example.com"
    _create_confirmed_user(ctx, pool_id, username, attributes=[{"Name": "email", "Value": email}])

    access_token = _sign_in(ctx, client_id, username)["AccessToken"]
    result = cognito.get_user_attribute_verification_code(AccessToken=access_token, AttributeName="email")

    details = result["CodeDeliveryDetails"]
    assert details["DeliveryMedium"] == "EMAIL", (
        f"expected EMAIL delivery medium for the email attribute, got {details['DeliveryMedium']!r}"
    )
    assert details["AttributeName"] == "email", (
        f"expected CodeDeliveryDetails to echo the requested attribute 'email', got {details['AttributeName']!r}"
    )
    assert details["Destination"], "expected a non-empty Destination in CodeDeliveryDetails, got none"


def _create_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_password_client(ctx, pool_id):
    cognito = ctx.client("cognito-idp")
    resp = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, attributes=None):
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=attributes or [],
        MessageAction="SUPPRESS",
        TemporaryPassword=_PASSWORD,
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)


def _sign_in(ctx, client_id, username):
    cognito = ctx.client("cognito-idp")
    resp = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
