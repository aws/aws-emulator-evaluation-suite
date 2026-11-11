"""op-contract-sign-up."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-sign-up"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SignUp creates an UNCONFIRMED user and returns a UserSub; re-registering the same
    username is rejected as a duplicate, the rejection leaves the existing record untouched,
    and once that record is removed the identical call succeeds again with a fresh identity."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-signup-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-")
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-signup-")
    password = "Sim2Real!Test123"

    resp = cognito.sign_up(ClientId=client_id, Username=username, Password=password)
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))

    assert resp["UserConfirmed"] is False, resp
    assert resp.get("UserSub"), resp
    original_sub = resp["UserSub"]

    described = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert described["UserStatus"] == "UNCONFIRMED", described

    # Break: signing up the same username twice is rejected with the specific error.
    code, message = _client_error(
        lambda: cognito.sign_up(ClientId=client_id, Username=username, Password=password)
    )
    assert code == "UsernameExistsException", code
    expected = "User already exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected retry did not touch the existing record.
    unchanged = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert unchanged["UserStatus"] == "UNCONFIRMED", unchanged
    unchanged_sub = {a["Name"]: a["Value"] for a in unchanged["UserAttributes"]}.get("sub")
    assert unchanged_sub == original_sub, (unchanged_sub, original_sub)

    # Restore: remove the existing record, prove it is gone, then the identical call succeeds.
    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
    not_found, not_found_message = _client_error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username))
    assert not_found == "UserNotFoundException", not_found
    expected = "User does not exist."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    restored = cognito.sign_up(ClientId=client_id, Username=username, Password=password)
    assert restored["UserConfirmed"] is False, restored
    assert restored.get("UserSub"), restored
    assert restored["UserSub"] != original_sub, (restored["UserSub"], original_sub)


def _client_error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
