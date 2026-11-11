"""delete-user-then-get-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-then-get-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A confirmed self-service DeleteUser removes the user; GetUser after delete is rejected."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    )

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    before = cognito.get_user(AccessToken=access_token)
    assert before["Username"] == username, f"expected positive control to read back {username!r}, got {before!r}"

    cognito.delete_user(AccessToken=access_token)

    # DeleteUser removes the user record, but the caller's access token is a stateless JWT that
    # isn't proactively revoked by this call; the token itself decodes fine, so the subsequent
    # GetUser lookup fails to resolve the (now-deleted) user rather than rejecting the token.
    # Real AWS can take a moment to propagate the deletion, so poll for the terminal error
    # instead of asserting on the first call.
    code, message = _poll_until_error(
        lambda: cognito.get_user(AccessToken=access_token), "UserNotFoundException"
    )
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    assert message == "User does not exist.", f"GetUser after DeleteUser: message {message!r}"

    # The deletion is not just a stale read: a mutation against the same (now-gone) identity
    # must also fail, and with the same not-found code an admin-path lookup would give.
    admin_code, admin_message = _error(
        lambda: cognito.admin_disable_user(UserPoolId=pool_id, Username=username)
    )
    assert admin_code == "UserNotFoundException", (
        f"expected AdminDisableUser on a deleted user to fail with UserNotFoundException, got {admin_code}"
    )
    assert admin_message == "User does not exist.", f"AdminDisableUser: message {admin_message!r}"


def _poll_until_error(fn, expected_code: str, timeout: float = 15.0, interval: float = 1.0):
    deadline = time.time() + timeout
    last = (None, None)
    while time.time() < deadline:
        try:
            fn()
        except ClientError as exc:
            last = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            if last[0] == expected_code:
                return last
        time.sleep(interval)
    return last


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
