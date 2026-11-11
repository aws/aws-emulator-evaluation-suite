"""e2e-signup-confirm-login-use-token-then-teardown."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-signup-confirm-login-use-token-then-teardown"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An access token from a signed-up, confirmed user resolves in GetUser, and after AdminDeleteUser
    the same token fails with UserNotFoundException and its exact message."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-signup-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-signup-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-signup-user-")
    password = "Sim2Real!Behav123"

    idp.sign_up(ClientId=client_id, Username=username, Password=password)
    idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)

    auth = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    user = idp.get_user(AccessToken=access_token)
    assert user["Username"] == username, f"expected GetUser to resolve {username!r}, got {user['Username']!r}"

    idp.admin_delete_user(UserPoolId=pool_id, Username=username)

    code, message = _poll_for_error(lambda: idp.get_user(AccessToken=access_token))
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code!r}"
    assert message == "User does not exist.", (
        f"expected the exact UserNotFoundException message 'User does not exist.', got {message!r}"
    )


def _poll_for_error(fn, timeout_s: float = 30.0, interval_s: float = 2.0) -> tuple[str, str]:
    """Deleting the user may take a beat to propagate to token validation, so poll
    until the call starts failing (bounded) and return its (code, message). A call that
    still succeeds at the deadline raises: the deleted user's token must stop resolving."""
    import time as _time

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        if _time.monotonic() >= deadline:
            raise AssertionError(
                f"expected a ClientError within {timeout_s}s, but the call kept succeeding: {result!r}"
            )
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
