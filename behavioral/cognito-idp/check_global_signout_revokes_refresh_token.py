"""global-signout-revokes-refresh-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-signout-revokes-refresh-token"
GROUP = 'auth-state-machine'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminUserGlobalSignOut invalidates previously issued refresh tokens."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), DeletionProtection="INACTIVE", UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    refresh_token = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["RefreshToken"]

    def refresh():
        return c.initiate_auth(
            ClientId=client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )

    before = refresh()
    assert before["AuthenticationResult"].get("AccessToken"), (
        "expected the refresh token to mint a new access token before sign-out, "
        f"got keys {sorted(before['AuthenticationResult'].keys())!r}"
    )

    c.admin_user_global_sign_out(UserPoolId=pool_id, Username=username)

    # Revocation can take a moment to propagate: a refresh that still succeeds inside the
    # window is retried, and the window closing without a refusal fails the check.
    deadline = time.monotonic() + 90
    last_seen = "no attempt"
    refusal = None
    while time.monotonic() < deadline:
        try:
            refresh()
            last_seen = "the refresh SUCCEEDED"
        except ClientError as exc:
            refusal = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            last_seen = f"refusal {refusal!r}"
            if refusal[0] == "NotAuthorizedException":
                break
        time.sleep(3)
    else:
        raise AssertionError(
            "expected NotAuthorizedException from a refresh token revoked by "
            f"AdminUserGlobalSignOut within 90s, last saw {last_seen}"
        )
    expected = "Refresh Token has been revoked"
    assert refusal[1] == expected, f"expected message {expected!r}, got {refusal[1]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
