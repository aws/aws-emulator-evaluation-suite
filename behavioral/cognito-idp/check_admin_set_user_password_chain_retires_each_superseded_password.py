"""admin-set-user-password-chain-retires-each-superseded-password."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-password-chain-retires-each-superseded-password"
GROUP = "password-lifecycle"
SERVICES = ["cognito-idp"]

FIRST_PASSWORD = "Fir5t-Perm4nent-Passw0rd!"
SECOND_PASSWORD = "Sec0nd-T3mporary-Passw0rd!"
THIRD_PASSWORD = "Thi4d-Perm4nent-Passw0rd!"

ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

_REFUSED = ("NotAuthorizedException", "Incorrect username or password.")


def _refusal(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    implementation accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the sign-in to be refused, but it SUCCEEDED and returned {result!r}")


def expect_error(fn, expected_code, expected_message) -> None:
    code, message = _refusal(fn)
    assert code == expected_code, f"expected error code {expected_code!r}, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminSetUserPassword(Permanent=False) retires the permanent password it replaces at once,
    and completing the resulting challenge with a further password retires that temporary one
    too, so neither superseded password signs the user in again.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/API_AdminSetUserPassword.html
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: idp.delete_user_pool(UserPoolId=_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: idp.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: idp.admin_delete_user(UserPoolId=_p, Username=_u))

    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=FIRST_PASSWORD, Permanent=True
    )

    # Positive control: the first permanent password authenticates before it is superseded,
    # so the later refusal is caused by the replacement below and not by a broken client/pool.
    first_auth = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": FIRST_PASSWORD},
    )
    assert first_auth.get("AuthenticationResult", {}).get("AccessToken"), (
        f"expected the first permanent password to authenticate, got {first_auth!r}"
    )

    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=SECOND_PASSWORD, Permanent=False
    )

    after_second = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after_second["UserStatus"] == "FORCE_CHANGE_PASSWORD", (
        f"expected UserStatus FORCE_CHANGE_PASSWORD after a non-permanent password replaced the "
        f"permanent one, got {after_second['UserStatus']!r}"
    )

    # The replaced permanent password must be dead immediately, with no intervening step.
    expect_error(
        lambda: idp.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": FIRST_PASSWORD},
        ),
        *_REFUSED,
    )

    challenge = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": SECOND_PASSWORD},
    )
    assert challenge.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", (
        f"expected ChallengeName NEW_PASSWORD_REQUIRED for the temporary password, got "
        f"{challenge.get('ChallengeName')!r}"
    )
    assert "AuthenticationResult" not in challenge, (
        "expected no AuthenticationResult while the NEW_PASSWORD_REQUIRED challenge is outstanding"
    )

    completed = idp.admin_respond_to_auth_challenge(
        UserPoolId=pool_id, ClientId=client_id, ChallengeName="NEW_PASSWORD_REQUIRED",
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": THIRD_PASSWORD},
        Session=challenge["Session"],
    )
    assert completed.get("AuthenticationResult", {}).get("AccessToken"), (
        f"expected tokens after answering NEW_PASSWORD_REQUIRED with a third password, got "
        f"{completed!r}"
    )

    after_third = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after_third["UserStatus"] == "CONFIRMED", (
        f"expected UserStatus CONFIRMED after the challenge set a permanent password, got "
        f"{after_third['UserStatus']!r}"
    )

    # The temporary password the challenge consumed is refused too, not only the original
    # permanent one.
    expect_error(
        lambda: idp.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": SECOND_PASSWORD},
        ),
        *_REFUSED,
    )

    # Positive control: the surviving password set by the challenge still authenticates.
    final_auth = idp.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": THIRD_PASSWORD},
    )
    assert final_auth.get("AuthenticationResult", {}).get("AccessToken"), (
        f"expected the third password to authenticate, got {final_auth!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
