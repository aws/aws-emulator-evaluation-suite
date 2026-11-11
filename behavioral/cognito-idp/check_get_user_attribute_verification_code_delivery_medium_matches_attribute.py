"""get-user-attribute-verification-code-delivery-medium-matches-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-attribute-verification-code-delivery-medium-matches-attribute"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetUserAttributeVerificationCode reports a CodeDeliveryDetails entry whose
    AttributeName is the attribute that was requested and whose DeliveryMedium is the
    medium appropriate for that attribute's type (EMAIL for an email attribute)."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Perm@nent1234"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPass!234",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    access_token = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    details = cognito.get_user_attribute_verification_code(
        AccessToken=access_token, AttributeName="email"
    )["CodeDeliveryDetails"]

    assert details["AttributeName"] == "email", (
        f"expected CodeDeliveryDetails to echo the requested attribute 'email', got {details['AttributeName']!r}"
    )
    assert details["DeliveryMedium"] == "EMAIL", (
        f"expected EMAIL delivery medium for the email attribute, got {details['DeliveryMedium']}"
    )
    assert details["Destination"], (
        f"expected a non-empty delivery destination for the email attribute, got {details['Destination']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
