"""start-webauthn-registration-invalid-access-token-not-authorized."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-webauthn-registration-invalid-access-token-not-authorized"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Test123"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartWebAuthnRegistration with an access token the pool never issued fails with
    NotAuthorizedException and its exact message and registers nothing, while the user's real token
    works for GetUser and returns CredentialCreationOptions."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id, username = _setup_confirmed_user(ctx)
    access_token = _get_access_token(ctx, pool_id, client_id, username)

    code, message = _error(lambda: cognito.start_web_authn_registration(AccessToken="not.a.real.token"))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected_message = "Invalid Access Token"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the real token still authorizes self-service calls
    who = cognito.get_user(AccessToken=access_token)
    assert who["Username"] == username

    # effect absent: the bogus attempt registered no WebAuthn credential
    creds = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert creds == []

    # positive control on the SAME operation: a genuinely valid access token is accepted by
    # StartWebAuthnRegistration itself and returns real registration options. Without this,
    # "rejects an unissued token" is indistinguishable from "rejects every
    # StartWebAuthnRegistration call, valid token or not."
    resp = cognito.start_web_authn_registration(AccessToken=access_token)
    assert "CredentialCreationOptions" in resp, resp

    # Delete the pool inline so a failed delete fails the check; the on_cleanup hook only
    # covers earlier failures.
    cognito.delete_user_pool(UserPoolId=pool_id)


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_pool_idempotent(cognito, pool_id: str) -> None:
    """The check deletes its pool inline; this cleanup only covers an earlier failure, so a
    pool that is already gone is not a teardown error."""
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _setup_confirmed_user(ctx):
    cognito = ctx.client("cognito-idp")
    # StartWebAuthnRegistration requires the pool's SignInPolicy to allow WEB_AUTHN as a
    # first-factor option (the choice-based USER_AUTH sign-in surface) or it rejects every call
    # with WebAuthnNotEnabledException regardless of WebAuthnConfiguration. No hosted domain is
    # needed for this — a domain's teardown is asynchronous on real AWS and outlives this check's
    # cleanup budget, so avoid creating one when the operation itself does not require it.
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]}},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_idempotent(cognito, pool_id))

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={"RelyingPartyId": "localhost", "UserVerification": "preferred"},
    )

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=_PASSWORD,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)
    return pool_id, client_id, username


def _get_access_token(ctx, pool_id, client_id, username):
    cognito = ctx.client("cognito-idp")
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
