"""sub-uuid-identical-in-admin-get-user-and-list-users-refused-as-username."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sub-uuid-identical-in-admin-get-user-and-list-users-refused-as-username"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_SETUP_PASSWORD = "Harbor-Lantern-91!"
_SUBSTITUTE_PASSWORD = "Quarry-Beacon-47!"
_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH"]

_NOT_FOUND = ("UserNotFoundException", "User does not exist.")
_BAD_CREDENTIALS = ("NotAuthorizedException", "Incorrect username or password.")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: keys {sorted(result)!r}")


def _sub_of(user_attrs: list) -> str:
    return next(a["Value"] for a in user_attrs if a["Name"] == "sub")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pool with no UsernameAttributes assigns each user a lowercase-UUID sub, distinct from
    Username and identical between AdminGetUser and ListUsers; AdminGetUser and
    AdminSetUserPassword both refuse the sub as Username, and no password change applies.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_SETUP_PASSWORD, Permanent=True
    )

    got = c.admin_get_user(UserPoolId=pool_id, Username=username)
    sub = _sub_of(got["UserAttributes"])
    parsed = uuid.UUID(sub)
    assert str(parsed) == sub, f"expected sub {sub!r} to be a canonical lowercase UUID string"
    assert sub != username, f"expected sub {sub!r} to differ from Username {username!r}"

    listed = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        listed = c.list_users(UserPoolId=pool_id, Filter=f'username = "{username}"')["Users"]
        if len(listed) == 1:
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"ListUsers did not converge on exactly one match for {username!r} within 60s; last saw {listed}"
        )
    assert listed[0]["Username"] == username, (
        f"ListUsers returned Username {listed[0]['Username']!r}, expected {username!r}"
    )
    listed_sub = _sub_of(listed[0]["Attributes"])
    assert listed_sub == sub, (
        f"ListUsers reports sub {listed_sub!r}, AdminGetUser reports {sub!r}; expected the same value"
    )

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _SETUP_PASSWORD},
    )
    assert "AuthenticationResult" in auth, (
        f"expected the setup password to authenticate before any sub-as-Username attempt, got {sorted(auth)!r}"
    )

    expect_error(lambda: c.admin_get_user(UserPoolId=pool_id, Username=sub), *_NOT_FOUND)
    expect_error(
        lambda: c.admin_set_user_password(
            UserPoolId=pool_id, Username=sub, Password=_SUBSTITUTE_PASSWORD, Permanent=True
        ),
        *_NOT_FOUND,
    )

    expect_error(
        lambda: c.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": _SUBSTITUTE_PASSWORD},
        ),
        *_BAD_CREDENTIALS,
    )
    auth_again = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _SETUP_PASSWORD},
    )
    assert "AuthenticationResult" in auth_again, (
        f"expected the setup password to still authenticate, got {sorted(auth_again)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
