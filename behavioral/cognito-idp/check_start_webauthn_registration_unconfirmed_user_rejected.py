"""start-webauthn-registration-unconfirmed-user-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-webauthn-registration-unconfirmed-user-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An UNCONFIRMED user's sign-in fails with UserNotConfirmedException and its exact message and leaves
    the user UNCONFIRMED, so no access token for StartWebAuthnRegistration exists, while a confirmed user
    with the same credentials gets one."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-unconfirmed-pool-"))[
        "UserPool"
    ]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-unconfirmed-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    password = "TestPassw0rd!23"

    # User A: self-signs-up, never confirmed -> stays UNCONFIRMED.
    user_a = ctx.unique_name("sim2real-unconfirmed-a-")
    cognito.sign_up(ClientId=client_id, Username=user_a, Password=password)
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=user_a))
    status_a = cognito.admin_get_user(UserPoolId=pool_id, Username=user_a)["UserStatus"]
    assert status_a == "UNCONFIRMED", f"expected freshly-signed-up user UNCONFIRMED, got {status_a}"

    code, message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": user_a, "PASSWORD": password},
        )
    )
    assert code == "UserNotConfirmedException", (
        f"expected UserNotConfirmedException for an unconfirmed user, got {code}"
    )
    expected_message = "User is not confirmed."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent, via an independent read: the rejected sign-in did not advance the
    # user's own status -- it is still exactly what it was before the attempt.
    status_a_after = cognito.admin_get_user(UserPoolId=pool_id, Username=user_a)["UserStatus"]
    assert status_a_after == "UNCONFIRMED", (
        f"a rejected sign-in must not change user status, got {status_a_after}"
    )

    # User B: identical setup, but admin-confirmed -> can sign in and get an AccessToken
    # (the prerequisite StartWebAuthnRegistration itself requires).
    user_b = ctx.unique_name("sim2real-unconfirmed-b-")
    cognito.sign_up(ClientId=client_id, Username=user_b, Password=password)
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=user_b))
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=user_b)

    auth = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user_b, "PASSWORD": password},
    )
    assert "AccessToken" in auth["AuthenticationResult"], (
        f"confirmed user sign-in did not return an AccessToken: {auth['AuthenticationResult']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
