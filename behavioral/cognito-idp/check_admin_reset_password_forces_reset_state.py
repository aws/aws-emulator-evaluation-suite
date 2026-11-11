"""admin-reset-password-forces-reset-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "admin-reset-password-forces-reset-state"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminResetUserPassword transitions a CONFIRMED user to RESET_REQUIRED status, as
    reflected by AdminGetUser, forcing the user to set a new password before their next
    successful sign-in."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-resetpw-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-resetpw-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-resetpw-user-")
    password = "Sim2Real-Pw!23456"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "CONFIRMED", before["UserStatus"]

    # positive control: with a permanent password set, sign-in succeeds without a challenge
    signed_in = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in signed_in, f"expected AuthenticationResult, got {signed_in}"

    idp.admin_reset_user_password(UserPoolId=pool_id, Username=username)

    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "RESET_REQUIRED", after["UserStatus"]

    # the old password can no longer complete a plain sign-in
    code, message = _error(
        lambda: idp.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert code == "PasswordResetRequiredException", code
    expected_message = "Password reset required for the user"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # restore: resolving the RESET_REQUIRED state (not incidental damage from the reset call)
    # is what unblocks sign-in — the identical call must succeed again once the state is CONFIRMED
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    restored = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert restored["UserStatus"] == "CONFIRMED", restored["UserStatus"]

    signed_in_again = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in signed_in_again, f"expected AuthenticationResult, got {signed_in_again}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
