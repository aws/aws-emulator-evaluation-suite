"""update-user-attributes-email-triggers-verification."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-user-attributes-email-triggers-verification"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With verification required before updates, UpdateUserAttributes on email returns one EMAIL code
    delivery for email and keeps the original email, still verified, until it is confirmed."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    original_email = f"{username}-orig@example.com"
    new_email = f"{username}-new@example.com"
    _admin_create_confirmed_user(
        ctx, pool_id, username, _PASSWORD, email=original_email, email_verified=True
    )
    auth = _admin_login(ctx, pool_id, client_id, username, _PASSWORD)
    access_token = auth["AccessToken"]

    resp = cognito.update_user_attributes(
        AccessToken=access_token,
        UserAttributes=[{"Name": "email", "Value": new_email}],
    )
    delivery_list = resp["CodeDeliveryDetailsList"]
    assert len(delivery_list) == 1, f"expected exactly 1 code delivery, got {delivery_list!r}"
    assert delivery_list[0]["AttributeName"] == "email", (
        f"expected the pending code delivery for 'email', got {delivery_list[0]!r}"
    )
    assert delivery_list[0]["DeliveryMedium"] == "EMAIL", (
        f"expected DeliveryMedium 'EMAIL', got {delivery_list[0]['DeliveryMedium']!r}"
    )

    user = cognito.get_user(AccessToken=access_token)
    attrs = {a["Name"]: a["Value"] for a in user["UserAttributes"]}
    assert attrs["email"] == original_email, (
        f"email should remain the original verified value pending confirmation, "
        f"got {attrs['email']!r}"
    )
    assert attrs["email_verified"] == "true", "original verified email should stay verified"


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    # Real Cognito requires every attribute named in
    # AttributesRequireVerificationBeforeUpdate to also be present in
    # AutoVerifiedAttributes (CreateUserPool otherwise rejects with
    # InvalidParameterException).
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        AutoVerifiedAttributes=["email"],
        UserAttributeUpdateSettings={"AttributesRequireVerificationBeforeUpdate": ["email"]},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _admin_create_confirmed_user(ctx, pool_id, username, password, email=None, email_verified=False):
    cognito = ctx.client("cognito-idp")
    attrs = []
    if email:
        attrs.append({"Name": "email", "Value": email})
        if email_verified:
            attrs.append({"Name": "email_verified", "Value": "true"})
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=attrs,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_login(ctx, pool_id, client_id, username, password):
    cognito = ctx.client("cognito-idp")
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
