"""admin-set-user-password-unknown-user-pool-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-password-unknown-user-pool-rejected"
GROUP = "password-lifecycle"
SERVICES = ["cognito-idp"]

REAL_PASSWORD = "Re4l-Pool-Passw0rd!"
ATTEMPTED_PASSWORD = "Bogus-P00l-Passw0rd!"


def _refusal(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    implementation accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def expect_error(fn, expected_code, expected_message) -> None:
    code, message = _refusal(fn)
    assert code == expected_code, f"expected error code {expected_code!r}, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminSetUserPassword against a syntactically valid but nonexistent UserPoolId is refused
    with ResourceNotFoundException and the exact message, and never touches the real pool's user.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: idp.delete_user_pool(UserPoolId=_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: idp.admin_delete_user(UserPoolId=_p, Username=_u))

    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=REAL_PASSWORD, Permanent=True
    )

    # A syntactically valid UserPoolId ("<region>_<alnum>") that no CreateUserPool call minted.
    bogus_pool_id = f"{ctx.region}_sim2realnonexistentpool"
    expected = ("ResourceNotFoundException", f"User pool {bogus_pool_id} does not exist.")

    expect_error(
        lambda: idp.admin_set_user_password(
            UserPoolId=bogus_pool_id, Username=username, Password=ATTEMPTED_PASSWORD, Permanent=True
        ),
        *expected,
    )

    # Effect-absent: the real pool's user is untouched, so the attempted call against the
    # nonexistent pool id did not somehow land on it.
    still_confirmed = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert still_confirmed["UserStatus"] == "CONFIRMED", (
        f"expected UserStatus CONFIRMED to be unaffected, got {still_confirmed['UserStatus']!r}"
    )

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: idp.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    # Positive control: the real password set before the bogus call still authenticates.
    control = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": REAL_PASSWORD},
    )
    assert control.get("AuthenticationResult", {}).get("AccessToken"), (
        f"expected the real pool's password to still authenticate, got {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
