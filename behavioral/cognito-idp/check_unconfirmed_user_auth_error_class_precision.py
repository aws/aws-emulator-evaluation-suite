"""unconfirmed-user-auth-error-class-precision."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "unconfirmed-user-auth-error-class-precision"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

NOT_CONFIRMED_MESSAGE = "User is not confirmed."
PASSWORD = "Sup3r-Secret-Passw0rd!"
WRONG_PASSWORD = "Wr0ng-Secret-Passw0rd!"
AUTH_FLOWS = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _error(fn) -> tuple:
    """Run fn and return the (code, message) AWS raised. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UNCONFIRMED user's InitiateAuth and AdminInitiateAuth fail with UserNotConfirmedException for the
    right and the wrong password alike, and an unknown user with UserNotFoundException; once confirmed,
    the right password gets tokens and the wrong one NotAuthorizedException, each with its exact message."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(AUTH_FLOWS),
        GenerateSecret=False,
        PreventUserExistenceErrors="LEGACY",
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    # No email/phone attribute and no AutoVerifiedAttributes: SignUp leaves the user
    # UNCONFIRMED without any out-of-band message being sent.
    username = ctx.unique_name("sim2real-behav-cipuser")
    signed_up = c.sign_up(ClientId=client_id, Username=username, Password=PASSWORD)
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    assert signed_up["UserConfirmed"] is False, (
        f"expected UserConfirmed False right after SignUp, got {signed_up['UserConfirmed']}"
    )
    assert (
        c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"] == "UNCONFIRMED"
    ), "test setup error: the freshly signed-up user is not UNCONFIRMED"

    def _initiate(password: str):
        return lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )

    # --- correct credential, unconfirmed status: the status error wins ---
    correct_code, correct_message = _error(_initiate(PASSWORD))
    assert correct_code == "UserNotConfirmedException", (
        f"InitiateAuth for an UNCONFIRMED user with the correct password must fail with "
        f"UserNotConfirmedException, got {correct_code}"
    )
    assert correct_message == NOT_CONFIRMED_MESSAGE, (
        f"expected the exact {correct_code} message, got {correct_message!r}"
    )
    admin_code, admin_message = _error(
        lambda: c.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    )
    assert admin_code == "UserNotConfirmedException", (
        f"AdminInitiateAuth must report the same UserNotConfirmedException for an UNCONFIRMED "
        f"user, got {admin_code}"
    )
    assert admin_message == NOT_CONFIRMED_MESSAGE, (
        f"expected the exact {admin_code} message, got {admin_message!r}"
    )

    # --- wrong credential: the STATUS check runs first, so the code does NOT change ---
    wrong_code, wrong_message = _error(_initiate(WRONG_PASSWORD))
    assert wrong_code == "UserNotConfirmedException", (
        f"InitiateAuth for an UNCONFIRMED user with the WRONG password must ALSO fail with "
        f"UserNotConfirmedException -- the status check precedes the credential check "
        f"(measured on real AWS), and answering NotAuthorizedException here would reveal "
        f"that the password was wrong, i.e. make the error code a password oracle on every "
        f"unconfirmed account; got {wrong_code}"
    )
    assert wrong_message == NOT_CONFIRMED_MESSAGE, (
        f"expected the exact {wrong_code} message, got {wrong_message!r}"
    )
    admin_wrong_code, admin_wrong_message = _error(
        lambda: c.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": WRONG_PASSWORD},
        )
    )
    assert admin_wrong_code == "UserNotConfirmedException", (
        f"AdminInitiateAuth must not leak the credential verdict either; the privileged "
        f"flow shows the same precedence, got {admin_wrong_code}"
    )
    assert admin_wrong_message == NOT_CONFIRMED_MESSAGE, (
        f"expected the exact {admin_wrong_code} message, got {admin_wrong_message!r}"
    )

    # ...and UserNotConfirmedException is a SPECIFIC verdict, not this client answering
    # every failure identically: an unknown username on the same client (LEGACY, so
    # existence is not masked) is UserNotFoundException.
    unknown_code, unknown_message = _error(
        lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username + "-absent", "PASSWORD": PASSWORD},
        )
    )
    assert unknown_code == "UserNotFoundException", (
        f"an unknown username must be UserNotFoundException, which is what proves the "
        f"UserNotConfirmedException above is a real verdict and not a blanket failure "
        f"code; got {unknown_code}"
    )
    assert unknown_message == "User does not exist.", (
        f"expected the exact {unknown_code} message, got {unknown_message!r}"
    )

    # --- effect absent: neither rejection advanced the account state ---
    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", (
        f"the rejected auth attempts must leave the user UNCONFIRMED, got {status}"
    )

    # --- control: confirming the account makes the SAME credential succeed ---
    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    assert (
        c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"] == "CONFIRMED"
    ), "AdminConfirmSignUp must transition the user to CONFIRMED"
    result = _initiate(PASSWORD)()["AuthenticationResult"]
    assert result.get("AccessToken"), (
        "the unchanged credential must authenticate once the user is CONFIRMED"
    )

    # --- and NOW the credential check is reachable, which is where the two codes
    # diverge. This is the assertion that makes the precedence above falsifiable: an
    # emulator that always answers UserNotConfirmedException fails here.
    confirmed_wrong_code, confirmed_wrong_message = _error(_initiate(WRONG_PASSWORD))
    assert confirmed_wrong_code == "NotAuthorizedException", (
        f"once the user is CONFIRMED the status check no longer short-circuits, so the "
        f"WRONG password must surface as NotAuthorizedException; got "
        f"{confirmed_wrong_code}"
    )
    assert confirmed_wrong_message == "Incorrect username or password.", (
        f"expected the exact {confirmed_wrong_code} message, got {confirmed_wrong_message!r}"
    )
    assert confirmed_wrong_code != wrong_code, (
        f"the same wrong password must produce DIFFERENT codes before and after "
        f"confirmation -- that difference is the whole precedence claim; both returned "
        f"{wrong_code}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
