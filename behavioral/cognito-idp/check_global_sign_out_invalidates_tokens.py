"""global-sign-out-invalidates-tokens."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-sign-out-invalidates-tokens"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After GlobalSignOut, a previously issued access token for that user is
    rejected on a subsequent GetUser call with NotAuthorizedException, though the
    same token worked immediately beforehand."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    _admin_create_confirmed_user(ctx, pool_id, username, _PASSWORD)
    auth = _admin_login(ctx, pool_id, client_id, username, _PASSWORD)
    access_token = auth["AccessToken"]

    # positive control: token works before sign-out
    before = cognito.get_user(AccessToken=access_token)
    assert before["Username"] == username, f"expected {username!r} pre-signout, got {before.get('Username')!r}"

    cognito.global_sign_out(AccessToken=access_token)

    code, message = _rejected_error(lambda: cognito.get_user(AccessToken=access_token))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected = "Access Token has been revoked"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_with_retry(cognito, pool_id))
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


_THROTTLE_CODES = {"TooManyRequestsException", "ThrottlingException", "LimitExceededException"}


def _delete_pool_with_retry(cognito, pool_id, attempts=5, interval_s=5.0):
    """DeleteUserPool retried against throttling: this account is shared by many concurrent
    checks, and cleanup is best-effort (exceptions are swallowed by the runner) so an unretried
    throttle here silently leaks the pool."""
    for attempt in range(attempts):
        try:
            cognito.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES or attempt == attempts - 1:
                raise
            time.sleep(interval_s)


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


def _rejected_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, naming the actual
    result."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the signed-out token to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
