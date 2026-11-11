"""start-webauthn-registration-invalid-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-webauthn-registration-invalid-token-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartWebAuthnRegistration with a bogus access token fails with NotAuthorizedException and registers
    nothing, while a real token on this pool without WEB_AUTHN fails with WebAuthnNotEnabledException,
    each with its exact message, and still works for GetUser."""
    cip = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_pool_client(ctx, pool_id)
    username = "carol"
    password = "Sim2Real123"
    token = _create_confirmed_user_and_login(ctx, pool_id, client_id, username, password)

    bogus_token = "invalidAccessToken.notreal.sim2real"
    code, message = _error(lambda: cip.start_web_authn_registration(AccessToken=bogus_token))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected_message = "Invalid Access Token"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected attempt registered no WebAuthn credential
    creds = cip.list_web_authn_credentials(AccessToken=token)["Credentials"]
    assert creds == [], f"expected no credentials after the rejected attempt, got {creds}"

    # positive control, on the *same operation*: a genuinely valid access token
    # for this user pool reaches a later stage of StartWebAuthnRegistration
    # (WebAuthnNotEnabledException, because this pool never enabled WEB_AUTHN as
    # a first-factor) instead of being stopped at the token-validation layer with
    # NotAuthorizedException. This is what actually distinguishes "the bogus
    # token is rejected" from "StartWebAuthnRegistration rejects every caller" --
    # GetUser succeeding with the valid token proves the token string is usable
    # elsewhere, but not that this operation treats it any differently than the
    # bogus one.
    same_op_code, same_op_message = _error(lambda: cip.start_web_authn_registration(AccessToken=token))
    assert same_op_code == "WebAuthnNotEnabledException", (
        f"expected the valid token to fail later, with WebAuthnNotEnabledException, "
        f"not NotAuthorizedException like the bogus token; got {same_op_code}"
    )
    expected_same_op_message = "WebAuthn not enabled for this pool."
    assert same_op_message == expected_same_op_message, f"expected message {expected_same_op_message!r}, got {same_op_message!r}"

    # and the token itself really is otherwise live
    user = cip.get_user(AccessToken=token)
    assert user["Username"] == username


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_pool_client(ctx, pool_id):
    cip = ctx.client("cognito-idp")
    return cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]


def _create_confirmed_user_and_login(ctx, pool_id, client_id, username, password, extra_attrs=None):
    cip = ctx.client("cognito-idp")
    cip.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=extra_attrs or [],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cip.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    resp = cip.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
