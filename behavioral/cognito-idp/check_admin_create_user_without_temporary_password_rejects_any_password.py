"""admin-create-user-without-temporary-password-rejects-any-password."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-create-user-without-temporary-password-rejects-any-password"
GROUP = 'auth-state-machine'
SERVICES = ['cognito-idp']

CALLER_GUESS = "Gu3ssed-Passw0rd!"
TEMP_PASSWORD = "S1bling-Temp0rary!"
NEW_PASSWORD = "Fin4l-Permanent-Passw0rd!"
AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


_INCORRECT_CREDS = ("NotAuthorizedException", "Incorrect username or password.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminCreateUser with no TemporaryPassword leaves FORCE_CHANGE_PASSWORD and refuses any
    sign-in, a sibling with one instead gets NEW_PASSWORD_REQUIRED, and only
    AdminSetUserPassword(Permanent=True) lets the first user sign in, landing at CONFIRMED.
    """
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    no_pw_username = ctx.unique_name("sim2real-behav-cip-nopw-")
    c.admin_create_user(UserPoolId=pool_id, Username=no_pw_username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=no_pw_username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    status_before = c.admin_get_user(UserPoolId=pool_id, Username=no_pw_username)["UserStatus"]
    assert status_before == "FORCE_CHANGE_PASSWORD", (
        f"expected a freshly admin-created user with no TemporaryPassword to start FORCE_CHANGE_PASSWORD, got {status_before!r}"
    )

    code, message = _error(lambda: c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": no_pw_username, "PASSWORD": CALLER_GUESS},
    ))
    assert (code, message) == _INCORRECT_CREDS, (
        f"expected {_INCORRECT_CREDS!r} for a caller-chosen password on a user with none set, got {(code, message)!r}"
    )

    status_after = c.admin_get_user(UserPoolId=pool_id, Username=no_pw_username)["UserStatus"]
    assert status_after == "FORCE_CHANGE_PASSWORD", (
        f"a rejected InitiateAuth must leave UserStatus at FORCE_CHANGE_PASSWORD, got {status_after!r}"
    )

    # The challenge neighbour: a sibling user given a TemporaryPassword is refused
    # differently -- a challenge, not the blanket NotAuthorizedException above -- which
    # rules out "every InitiateAuth against this pool/client fails the same way".
    sibling_username = ctx.unique_name("sim2real-behav-cip-sibling-")
    c.admin_create_user(UserPoolId=pool_id, Username=sibling_username, MessageAction="SUPPRESS", TemporaryPassword=TEMP_PASSWORD)
    ctx.on_cleanup(lambda _p=pool_id, _u=sibling_username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    sibling_challenge = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": sibling_username, "PASSWORD": TEMP_PASSWORD},
    )
    assert sibling_challenge.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", (
        f"expected the sibling's TemporaryPassword to raise NEW_PASSWORD_REQUIRED, got {sibling_challenge.get('ChallengeName')!r}"
    )
    assert "AuthenticationResult" not in sibling_challenge, (
        "expected no AuthenticationResult while the sibling's challenge is outstanding"
    )

    # Restore: AdminSetUserPassword(Permanent=True) is what finally lets the first
    # user in, and it lands on CONFIRMED rather than back on FORCE_CHANGE_PASSWORD.
    c.admin_set_user_password(UserPoolId=pool_id, Username=no_pw_username, Password=NEW_PASSWORD, Permanent=True)
    signed_in = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": no_pw_username, "PASSWORD": NEW_PASSWORD},
    )
    assert signed_in.get("ChallengeName") is None, (
        f"expected no challenge once a permanent password is set, got {signed_in.get('ChallengeName')!r}"
    )
    assert signed_in["AuthenticationResult"]["AccessToken"], (
        "expected an AccessToken once a permanent password is set"
    )
    status_final = c.admin_get_user(UserPoolId=pool_id, Username=no_pw_username)["UserStatus"]
    assert status_final == "CONFIRMED", (
        f"expected UserStatus CONFIRMED after a permanent password is set and used to sign in, got {status_final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
