"""start-webauthn-registration-without-access-token-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-webauthn-registration-without-access-token-denied"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartWebAuthnRegistration returns CredentialCreationOptions for a real access token, and fails with
    NotAuthorizedException and its exact message for a garbage token, registering no credential."""
    cognito = ctx.client("cognito-idp")

    pool_id, _domain = _create_webauthn_pool(ctx, cognito)
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    access_token = _create_confirmed_user_token(ctx, cognito, pool_id, client_id)

    # positive control: the real, valid access token succeeds
    resp = cognito.start_web_authn_registration(AccessToken=access_token)
    assert "CredentialCreationOptions" in resp, f"expected CredentialCreationOptions, got {sorted(resp)}"

    bogus_token = "not-a-real-access-token-" + "x" * 20
    code, message = _error(lambda: cognito.start_web_authn_registration(AccessToken=bogus_token))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected_message = "Invalid Access Token"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected attempt registered no WebAuthn credential for the real
    # user (independent read, through list_web_authn_credentials rather than start again)
    creds = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert creds == [], f"expected no WebAuthn credentials, got {creds}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_webauthn_pool(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-webauthn-"),
        UserPoolTier="ESSENTIALS",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2realwa").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
        WebAuthnConfiguration={
            "RelyingPartyId": f"{domain}.auth.{ctx.region}.amazoncognito.com",
            "UserVerification": "preferred",
            "FactorConfiguration": "SINGLE_FACTOR",
        },
    )
    # passkeys are only usable via the choice-based (USER_AUTH) sign-in flow; the pool's
    # SignInPolicy must explicitly allow WEB_AUTHN as a first-factor option or
    # StartWebAuthnRegistration rejects with WebAuthnNotEnabledException
    cognito.update_user_pool(
        UserPoolId=pool_id,
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
    )
    return pool_id, domain


def _create_confirmed_user_token(ctx, cognito, pool_id, client_id, password="Sim2Real-Pwd9!"):
    username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
