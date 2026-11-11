"""op-contract-respond-to-auth-challenge."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-respond-to-auth-challenge"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RespondToAuthChallenge completes the NEW_PASSWORD_REQUIRED challenge and confirms the user;
    an invalid session token is rejected."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-user-")
    temp_password = _password()
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=temp_password,
        MessageAction="SUPPRESS",
    )

    before = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "FORCE_CHANGE_PASSWORD", before["UserStatus"]

    initiated = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": temp_password},
    )
    assert initiated["ChallengeName"] == "NEW_PASSWORD_REQUIRED", initiated["ChallengeName"]
    session = initiated["Session"]

    new_password = "Sim2Real!24Bb"
    responded = idp.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=session,
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": new_password},
    )
    result = responded["AuthenticationResult"]
    assert result.get("AccessToken"), "expected AccessToken after completing the challenge"

    after = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED", after["UserStatus"]

    # A bogus session token isn't rejected as an auth failure — Cognito parses it as an
    # (invalid) challenge-response code and rejects it as a mismatch, per real AWS behavior.
    err = _client_error(
        lambda: idp.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session="not-a-real-session-token",
            ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": "AnotherPassw0rd!23"},
        )
    )
    assert err.get("Code") == "CodeMismatchException", f"expected CodeMismatchException, got {err!r}"
    want = "Invalid code/session provided"
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _password() -> str:
    return "Sim2Real!23Aa"


def _create_user_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "UserPoolId": pool_id,
        "ClientName": ctx.unique_name("sim2real-behav-client-"),
        "ExplicitAuthFlows": [
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ],
    }
    params.update(overrides)
    resp = idp.create_user_pool_client(**params)
    return resp["UserPoolClient"]["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
