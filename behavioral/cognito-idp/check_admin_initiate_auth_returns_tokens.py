"""admin-initiate-auth-returns-tokens."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


PASSWORD = "Sup3r-Secret-Passw0rd!"

CHECK = "admin-initiate-auth-returns-tokens"
GROUP = 'auth-state-machine'
SERVICES = ['cognito-idp']

ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _retry_transient(fn, *, deadline_s=20.0, initial_delay_s=1.0) -> None:
    """Cognito pool-scoped deletes race the admin mutations this check just made on the
    same pool and can answer ConcurrentModificationException/TooManyRequestsException for a
    few seconds; ctx.on_cleanup swallows the exception, so an unretried delete leaks silently."""
    deadline = time.monotonic() + deadline_s
    delay = initial_delay_s
    while True:
        try:
            fn()
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 5.0)


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CONFIRMED user authenticates straight to tokens with a 1-hour access token."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _retry_transient(lambda: c.delete_user_pool(UserPoolId=_id)))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: _retry_transient(lambda: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: _retry_transient(lambda: c.admin_delete_user(UserPoolId=_p, Username=_u)))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    resp = c.admin_initiate_auth(UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH", AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD})
    assert "ChallengeName" not in resp, (
        f"expected no challenge for a CONFIRMED user, got {resp.get('ChallengeName')}"
    )
    result = resp["AuthenticationResult"]
    for field in ("AccessToken", "IdToken", "RefreshToken"):
        assert result.get(field), f"expected {field} in AuthenticationResult"
    assert result.get("TokenType") == "Bearer", (
        f"expected TokenType Bearer, got {result.get('TokenType')}"
    )
    assert result.get("ExpiresIn") == 3600, (
        f"expected default access-token lifetime of 3600s, got {result.get('ExpiresIn')}"
    )

    me = c.get_user(AccessToken=result["AccessToken"])
    assert me["Username"] == username, (
        f"expected GetUser to resolve {username}, got {me['Username']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
