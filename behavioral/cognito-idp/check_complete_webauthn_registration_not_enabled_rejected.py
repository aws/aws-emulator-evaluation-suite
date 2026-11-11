"""complete-webauthn-registration-not-enabled-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-webauthn-registration-not-enabled-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CompleteWebAuthnRegistration on a pool without WebAuthn is refused with
    WebAuthnNotEnabledException and the exact message; once WebAuthn is enabled the same malformed
    call answers InvalidParameterException, and no credential is stored."""
    cip = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_pool_client(ctx, pool_id)
    username = "dave"
    password = "Sim2Real123"
    token = _create_confirmed_user_and_login(ctx, pool_id, client_id, username, password)
    credential = {"not": "a-real-attestation"}

    # Credential is a malformed/incomplete attestation payload -- irrelevant,
    # because WebAuthn was never enabled on this pool at all.
    code, code_msg = _error_code(
        lambda: cip.complete_web_authn_registration(AccessToken=token, Credential=credential)
    )
    assert code == "WebAuthnNotEnabledException", f"expected WebAuthnNotEnabledException, got {code}"
    assert code_msg == 'WebAuthn not enabled for this pool.', f"expected the exact {code} message, got {code_msg!r}"

    # effect absent: no WebAuthn credential was ever recorded for the user
    creds = cip.list_web_authn_credentials(AccessToken=token)
    assert creds["Credentials"] == []

    # positive control: the same token still works for an unrelated user-facing call
    factors = cip.get_user_auth_factors(AccessToken=token)
    assert factors["Username"] == username

    # Restore: enable WebAuthn on the same pool and resend the identical malformed call; the gate
    # is checked first, so the error moves to the next validation layer instead of succeeding.
    cip.update_user_pool(
        UserPoolId=pool_id,
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            },
            "SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD", "WEB_AUTHN"]},
        },
    )
    cip.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        WebAuthnConfiguration={
            "RelyingPartyId": "localhost",
            "UserVerification": "preferred",
            "FactorConfiguration": "SINGLE_FACTOR",
        },
    )
    code_after_enable, code_after_enable_msg = _error_code(
        lambda: cip.complete_web_authn_registration(AccessToken=token, Credential=credential)
    )
    assert code_after_enable != "WebAuthnNotEnabledException", (
        f"gate still reports not-enabled after enabling WebAuthn on the pool: {code_after_enable}"
    )
    assert code_after_enable == "InvalidParameterException", (
        "expected the next validation layer (the credential's own shape, checked ahead of "
        f"challenge lookup) once the feature gate is lifted, got {code_after_enable}"
    )
    assert code_after_enable_msg == 'Credential data is not valid', f"expected the exact {code_after_enable} message, got {code_after_enable_msg!r}"

    # still no credential recorded after the second rejection
    creds_after_enable = cip.list_web_authn_credentials(AccessToken=token)
    assert creds_after_enable["Credentials"] == []


def _error_code(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cog-pool"},
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_pool_client(ctx, pool_id):
    cip = ctx.client("cognito-idp")
    return cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_AUTH",
        ],
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
