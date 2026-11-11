"""weak-password-signup-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "weak-password-signup-rejected"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SignUp with a password violating the policy fails with InvalidPasswordException and its exact
    message and creates no user, while a compliant password for another username leaves an UNCONFIRMED
    user."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pwpolicy-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 12,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-pwpolicy-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )

    weak_username = ctx.unique_name("s2rweakpw")
    code, message = _error(
        lambda: cognito.sign_up(
            ClientId=client_id,
            Username=weak_username,
            Password="abc123",
            UserAttributes=[{"Name": "email", "Value": f"{weak_username}@example.com"}],
        ),
        expect="InvalidPasswordException for a policy-violating password",
    )
    assert code == "InvalidPasswordException", (
        f"SignUp with a password violating the pool's PasswordPolicy must be rejected with "
        f"InvalidPasswordException, got {code!r}"
    )
    expected = "Password did not conform with policy: Password not long enough"
    assert message == expected, (
        f"InvalidPasswordException message: expected {expected!r}, got {message!r}"
    )

    # Effect absent: no user was created for the rejected SignUp.
    not_found_code, not_found_message = _error(
        lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=weak_username),
        expect="UserNotFoundException (no user created for a rejected SignUp)",
    )
    assert not_found_code == "UserNotFoundException", (
        f"a rejected SignUp must not create a user; AdminGetUser({weak_username!r}) should have "
        f"raised UserNotFoundException, got {not_found_code!r}"
    )
    assert not_found_message == "User does not exist.", (
        f"UserNotFoundException message: expected 'User does not exist.', got {not_found_message!r}"
    )

    # Positive control: a compliant password succeeds in the same pool/client, proving the
    # rejection above is about the password and not a blanket SignUp failure.
    strong_username = ctx.unique_name("s2rstrongpw")
    signup = cognito.sign_up(
        ClientId=client_id,
        Username=strong_username,
        Password="Str0ng!Passw0rdXY",
        UserAttributes=[{"Name": "email", "Value": f"{strong_username}@example.com"}],
    )
    assert signup["UserConfirmed"] is False, (
        f"a fresh SignUp with AutoVerifiedAttributes=[email] must be unconfirmed pending "
        f"verification, got UserConfirmed={signup['UserConfirmed']!r}"
    )
    status = cognito.admin_get_user(UserPoolId=pool_id, Username=strong_username)["UserStatus"]
    assert status == "UNCONFIRMED", (
        f"a compliant SignUp must leave AdminGetUser UserStatus=UNCONFIRMED, got {status!r}"
    )


def _error(fn, *, expect):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected {expect}, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
