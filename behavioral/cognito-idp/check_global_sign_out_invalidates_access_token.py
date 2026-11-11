"""global-sign-out-invalidates-access-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-sign-out-invalidates-access-token"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After AdminUserGlobalSignOut (and, independently, GlobalSignOut) a previously
    valid access token must be rejected by GetUser instead of still working."""
    idp = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username, password = _create_confirmed_user(ctx, pool_id)

    # --- AdminUserGlobalSignOut variant ---
    auth1 = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token_1 = auth1["AuthenticationResult"]["AccessToken"]
    me = idp.get_user(AccessToken=access_token_1)
    assert me["Username"] == username, f"expected {username!r}, got {me['Username']!r}"

    idp.admin_user_global_sign_out(UserPoolId=pool_id, Username=username)

    code1, message1 = _error(lambda: idp.get_user(AccessToken=access_token_1))
    assert code1 == "NotAuthorizedException", (
        f"expected NotAuthorizedException after AdminUserGlobalSignOut, got {code1!r}"
    )
    expected = "Access Token has been revoked"
    assert message1 == expected, f"expected message {expected!r}, got {message1!r}"

    # --- GlobalSignOut variant (independent sign-in) ---
    # AdminUserGlobalSignOut applies an "issued before now" cutoff to the whole user; on
    # real AWS that cutoff timestamp can momentarily lag behind (clock-skew/propagation),
    # so a token minted immediately afterwards can spuriously appear "issued before" the
    # cutoff and get treated as already revoked. Poll a fresh sign-in until GetUser
    # actually succeeds with the new token before proceeding with the GlobalSignOut half
    # of this check.
    access_token_2 = _poll_for_valid_access_token(idp, client_id, username, password)
    me2 = idp.get_user(AccessToken=access_token_2)
    assert me2["Username"] == username, f"expected {username!r}, got {me2['Username']!r}"

    idp.global_sign_out(AccessToken=access_token_2)

    code2, message2 = _error(lambda: idp.get_user(AccessToken=access_token_2))
    assert code2 == "NotAuthorizedException", (
        f"expected NotAuthorizedException after GlobalSignOut, got {code2!r}"
    )
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"


def _poll_for_valid_access_token(idp, client_id, username, password, timeout=20.0, interval=1.0):
    deadline = time.time() + timeout
    last_code = None
    while time.time() < deadline:
        auth = idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=client_id,
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        token = auth["AuthenticationResult"]["AccessToken"]
        try:
            idp.get_user(AccessToken=token)
            return token
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
        time.sleep(interval)
    raise AssertionError(f"newly issued access token never became valid, last error: {last_code!r}")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _create_pool_and_client(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))
    return pool_id, client_id


def _create_confirmed_user(ctx, pool_id):
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username,
        TemporaryPassword="Temp0rary!Passw0rd", MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
