"""user-settings-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "user-settings-roundtrip"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserSettings/AdminSetUserSettings persist MFA delivery preferences reflected on GetUser."""
    idp = ctx.client("cognito-idp")

    # Real Cognito rejects SetUserSettings/AdminSetUserSettings MFAOptions writes outright
    # ("Cannot change the MFA setting when the user pool MFA is off") unless the pool's
    # MfaConfiguration is OPTIONAL or ON. Getting there via CreateUserPool would additionally
    # require SMS configuration (an SnsCallerArn IAM role) plus phone_number in
    # AutoVerifiedAttributes, so instead the pool is created with its default MfaConfiguration
    # (OFF) and then flipped to OPTIONAL via SetUserPoolMfaConfig using SoftwareTokenMfaConfiguration
    # (which needs no SMS/SNS role) -- this only changes whether per-user MFA preferences are
    # legal to set at all, it doesn't require the SMS delivery medium itself to be provisioned.
    pool_name = ctx.unique_name("sim2real-behav-usersettings-")
    pool_id = idp.create_user_pool(
        PoolName=pool_name,
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("user-")
    password = "TempPassw0rd!123"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "phone_number", "Value": "+15005550006"},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    # SetUserSettings (self-service, token-authorized) registers an SMS MFA delivery preference.
    idp.set_user_settings(
        AccessToken=access_token,
        MFAOptions=[{"DeliveryMedium": "SMS", "AttributeName": "phone_number"}],
    )
    # NOTE: Real Cognito treats "MFAOptions" as an optional, no-longer-actively-maintained
    # response field: when there are no SMS MFA options configured for the user, the key is
    # omitted from the GetUser/AdminGetUser response entirely rather than being returned as an
    # empty list. Use .get(..., []) so "no MFAOptions configured" is treated uniformly whether
    # the API expresses that as an absent key or an explicit empty list.
    self_view = idp.get_user(AccessToken=access_token)
    assert self_view.get("MFAOptions", []) == [
        {"DeliveryMedium": "SMS", "AttributeName": "phone_number"}
    ], f"expected SMS MFAOptions on GetUser after SetUserSettings, got {self_view.get('MFAOptions')!r}"

    admin_view = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert admin_view.get("MFAOptions", []) == [
        {"DeliveryMedium": "SMS", "AttributeName": "phone_number"}
    ], f"expected SMS MFAOptions on AdminGetUser after SetUserSettings, got {admin_view.get('MFAOptions')!r}"

    # AdminSetUserSettings (server-side) overwrites/clears the same server-enforced preference.
    idp.admin_set_user_settings(UserPoolId=pool_id, Username=username, MFAOptions=[])
    cleared_admin_view = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert cleared_admin_view.get("MFAOptions", []) == [], (
        f"expected no MFAOptions on AdminGetUser after AdminSetUserSettings clear, "
        f"got {cleared_admin_view.get('MFAOptions')!r}"
    )
    cleared_self_view = idp.get_user(AccessToken=access_token)
    assert cleared_self_view.get("MFAOptions", []) == [], (
        f"expected no MFAOptions on GetUser after AdminSetUserSettings clear, "
        f"got {cleared_self_view.get('MFAOptions')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
