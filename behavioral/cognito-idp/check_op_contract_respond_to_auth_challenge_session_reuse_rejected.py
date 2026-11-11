"""op-contract-respond-to-auth-challenge-session-reuse-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-respond-to-auth-challenge-session-reuse-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RespondToAuthChallenge completes NEW_PASSWORD_REQUIRED with Bearer tokens; replaying the consumed
    Session fails with NotAuthorizedException and its exact message, and the account still signs in
    with the first password while the replayed one fails the same way."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-user-")
    temp_password = "TempPassw0rd!"
    new_password = "NewPassw0rd!9"
    replay_password = "AnotherPassw0rd!1"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=temp_password,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    init = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": temp_password},
    )
    assert init["ChallengeName"] == "NEW_PASSWORD_REQUIRED", init
    session = init["Session"]

    resp = idp.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=session,
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": new_password},
    )
    result = resp["AuthenticationResult"]
    assert result["TokenType"] == "Bearer", f"expected Bearer, got {result.get('TokenType')!r}"
    assert result["AccessToken"] and result["IdToken"] and result["RefreshToken"], (
        f"expected AccessToken, IdToken and RefreshToken all populated, got {result!r}"
    )

    # Boundary: the Session was single-use; replaying it is a state conflict, not a
    # generic validation failure.
    code, message = _error(
        lambda: idp.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=session,
            ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": replay_password},
        )
    )
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected = "Invalid session for the user, session can only be used once."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected replay must not have taken effect. Prove it with an
    # independent read through InitiateAuth (never the mutating RespondToAuthChallenge) — the
    # account still authenticates with the FIRST response's password, and the replay's password
    # was never adopted.
    still_works = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": new_password},
    )
    still_result = still_works["AuthenticationResult"]
    assert still_result["AccessToken"], (
        f"expected the FIRST response's password to still authenticate, got {still_works!r}"
    )

    replay_code, replay_message = _error(
        lambda: idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            ClientId=client_id,
            AuthParameters={"USERNAME": username, "PASSWORD": replay_password},
        )
    )
    assert replay_code == "NotAuthorizedException", (
        f"the rejected replay's password must never have been adopted; "
        f"expected NotAuthorizedException, got {replay_code}"
    )
    expected = "Incorrect username or password."
    assert replay_message == expected, f"expected message {expected!r}, got {replay_message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
