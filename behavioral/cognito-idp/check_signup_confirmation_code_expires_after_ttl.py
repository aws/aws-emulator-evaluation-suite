"""signup-confirmation-code-expires-after-ttl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signup-confirmation-code-expires-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SignUp leaves the user UNCONFIRMED with EMAIL CodeDeliveryDetails, and ConfirmSignUp with a wrong
    code against the fresh code fails with CodeMismatchException, not ExpiredCodeException, and its
    exact message, leaving the user UNCONFIRMED."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        AutoVerifiedAttributes=["email"],
        Schema=[{"Name": "email", "Required": True, "Mutable": True}],
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))

    username = ctx.unique_name("sim2real-user-")
    email = f"{username}@example.com"
    password = "Sim2Real!Passw0rd"
    signup = idp.sign_up(
        ClientId=client_id,
        Username=username,
        Password=password,
        UserAttributes=[{"Name": "email", "Value": email}],
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)))
    assert signup["UserConfirmed"] is False, "a fresh self-signed-up user must start UNCONFIRMED"
    assert "CodeDeliveryDetails" in signup, "sign_up did not report a confirmation code delivery"
    assert signup["CodeDeliveryDetails"]["DeliveryMedium"] == "EMAIL", signup["CodeDeliveryDetails"]

    described = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert described["UserStatus"] == "UNCONFIRMED", (
        f"expected UNCONFIRMED for a just-signed-up, not-yet-confirmed user, got {described['UserStatus']!r}"
    )

    code, message = _error(lambda: idp.confirm_sign_up(
        ClientId=client_id, Username=username, ConfirmationCode="000000",
    ))
    assert code == "CodeMismatchException", (
        f"expected CodeMismatchException for a wrong-but-not-yet-expired code, got {code!r}"
    )
    expected_message = "Invalid verification code provided, please try again."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected attempt must be a no-op: an independent read, through a different
    # operation than the one that was rejected, confirms the user is still UNCONFIRMED.
    after_reject = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after_reject["UserStatus"] == "UNCONFIRMED", (
        "a rejected (mismatched) confirmation code must not confirm the user; expected "
        f"UNCONFIRMED, got {after_reject['UserStatus']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
