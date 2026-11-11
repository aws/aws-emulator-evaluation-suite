"""associate-software-token-no-credentials-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-software-token-no-credentials-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _err(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateSoftwareToken with an AccessToken returns a SecretCode, and with neither AccessToken
    nor Session it is refused with NotAuthorizedException "Invalid Access Token"."""
    c = ctx.client("cognito-idp")
    password = "Sim2RealP@ss9142"

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-assoc-pool-"), UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-assoc-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("assocuser-")
    c.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    access_token = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    # Positive control: the pool/user/credentials are healthy, and AssociateSoftwareToken with a
    # real AccessToken succeeds and mints a secret -- so the negative below cannot be "everything
    # is rejected".
    positive = c.associate_software_token(AccessToken=access_token)
    assert positive.get("SecretCode"), (
        f"expected AssociateSoftwareToken(AccessToken=...) to mint a SecretCode, got {positive}"
    )

    # Negative: the identical call with NEITHER AccessToken NOR Session must be rejected with the
    # specific error, not silently mint a secret detached from any user/session.
    code, code_msg = _err(lambda: c.associate_software_token())
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException calling AssociateSoftwareToken with no AccessToken "
        f"and no Session, got {code}"
    )
    assert code_msg == 'Invalid Access Token', f"expected the exact {code} message, got {code_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
