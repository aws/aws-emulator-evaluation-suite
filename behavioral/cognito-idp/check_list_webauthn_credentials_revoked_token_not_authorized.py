"""list-webauthn-credentials-revoked-token-not-authorized."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-webauthn-credentials-revoked-token-not-authorized"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Test123"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListWebAuthnCredentials accepts an access token before GlobalSignOut and afterwards fails with
    NotAuthorizedException and the exact message "Access Token has been revoked"."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id, username = _setup_confirmed_user(ctx)
    access_token = _get_access_token(ctx, pool_id, client_id, username)

    # positive control: valid, freshly-issued token is authorized
    creds_before = cognito.list_web_authn_credentials(AccessToken=access_token)["Credentials"]
    assert creds_before == [], f"expected no credentials before sign-out, got {creds_before!r}"

    cognito.global_sign_out(AccessToken=access_token)

    def _probe():
        return _error_code(lambda: cognito.list_web_authn_credentials(AccessToken=access_token))

    refusal = _poll_until(
        _probe, lambda r: r is not None and r[0] == "NotAuthorizedException", timeout_s=20.0, interval_s=1.0
    )
    assert refusal is not None, "ListWebAuthnCredentials still accepted the token after GlobalSignOut"
    code, message = refusal
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException after sign-out, got {code}"
    assert message == "Access Token has been revoked", message


def _error_code(fn):
    """(code, message) of fn()'s refusal, or None while the call still succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _setup_confirmed_user(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
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
