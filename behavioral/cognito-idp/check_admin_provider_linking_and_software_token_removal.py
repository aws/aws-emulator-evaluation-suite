"""admin-provider-linking-and-software-token-removal."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-provider-linking-and-software-token-removal"
GROUP = 'mfa-config'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
PASSWORD = "Str0ngPassw0rd!"
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _retry_throttled(fn, *, max_attempts=8, base_delay=1.0):
    import time

    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


def _totp_now(secret_b32, digits=6, step=30, offset=0):
    import base64
    import hashlib
    import hmac
    import struct
    import time

    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[o : o + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _setup_software_token_mfa(c, access_token):
    """AssociateSoftwareToken + VerifySoftwareToken(SUCCESS) + SetUserMFAPreference(Preferred).
    Returns the base32 TOTP secret. Requires the pool's MFA already turned on."""
    secret = c.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify = c.verify_software_token(AccessToken=access_token, UserCode=_totp_now(secret))
    assert verify["Status"] == "SUCCESS", verify
    c.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    return secret


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = _retry_throttled(
        lambda: c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs)
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = _retry_throttled(
        lambda: c.create_user_pool_client(
            UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
        )
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


def _new_social_idp(ctx, c, pool_id, provider_name="Facebook", provider_type="Facebook"):
    _retry_throttled(
        lambda: c.create_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            ProviderType=provider_type,
            ProviderDetails={
                "client_id": "sim2real-fake-app-id",
                "client_secret": "sim2real-fake-app-secret",
                "authorize_scopes": "public_profile,email",
            },
            AttributeMapping={"email": "email"},
        )
    )
    ctx.on_cleanup(
        lambda: c.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
    )
    return provider_name


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _user_login(c, client_id, username, password):
    resp = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminLinkProviderForUser adds a federated identity to AdminGetUser's identities attribute and
    AdminDisableProviderForUser removes it; GetUserAuthFactors reflects software-token MFA being
    enabled, then disabled via AdminSetUserMFAPreference."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    _retry_throttled(
        lambda: c.set_user_pool_mfa_config(
            UserPoolId=pool_id,
            SoftwareTokenMfaConfiguration={"Enabled": True},
            MfaConfiguration="OPTIONAL",
        )
    )
    _new_social_idp(ctx, c, pool_id, provider_name="Facebook", provider_type="Facebook")
    username, password = _new_confirmed_user(ctx, c, pool_id)

    provider_user_id = ctx.unique_name("sim2real-behav-fb-uid-")
    c.admin_link_provider_for_user(
        UserPoolId=pool_id,
        DestinationUser={"ProviderName": "Cognito", "ProviderAttributeValue": username},
        SourceUser={
            "ProviderName": "Facebook",
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": provider_user_id,
        },
    )
    linked = c.admin_get_user(UserPoolId=pool_id, Username=username)
    # The link is reflected in the "identities" JSON user attribute rather than a top-level field.
    identities_attr = next(
        (a["Value"] for a in linked["UserAttributes"] if a["Name"] == "identities"), None
    )
    assert identities_attr and "Facebook" in identities_attr, (
        f"expected the Facebook link reflected in the identities attribute, got: {linked}"
    )

    c.admin_disable_provider_for_user(
        UserPoolId=pool_id,
        User={
            "ProviderName": "Facebook",
            "ProviderAttributeName": "Cognito_Subject",
            "ProviderAttributeValue": provider_user_id,
        },
    )
    unlinked = c.admin_get_user(UserPoolId=pool_id, Username=username)
    unlinked_identities_attr = next(
        (a["Value"] for a in unlinked["UserAttributes"] if a["Name"] == "identities"), None
    )
    assert not (unlinked_identities_attr and "Facebook" in unlinked_identities_attr), (
        f"expected the Facebook link removed from identities after AdminDisableProviderForUser, "
        f"got: {unlinked}"
    )

    auth = _user_login(c, client_id, username, password)
    # AdminGetUserAuthFactors is not exposed by the SDK, so read the AccessToken-keyed variant.
    pre_factors = c.get_user_auth_factors(AccessToken=auth["AccessToken"])
    assert pre_factors.get("UserMFASettingList", []) == [], pre_factors

    _setup_software_token_mfa(c, auth["AccessToken"])
    mid_factors = c.get_user_auth_factors(AccessToken=auth["AccessToken"])
    assert "SOFTWARE_TOKEN_MFA" in mid_factors["UserMFASettingList"], mid_factors

    c.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": False},
    )
    post_factors = c.get_user_auth_factors(AccessToken=auth["AccessToken"])
    assert "SOFTWARE_TOKEN_MFA" not in post_factors.get("UserMFASettingList", []), post_factors


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
