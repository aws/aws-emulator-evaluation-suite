"""op-contract-admin-respond-to-auth-challenge."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-admin-respond-to-auth-challenge"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminRespondToAuthChallenge with a garbage Session is refused with CodeMismatchException and
    the exact message, and with the real NEW_PASSWORD_REQUIRED session it returns tokens and leaves
    the user CONFIRMED."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_pool_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-user-")
    temp_password = "TempPassw0rd!"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=temp_password,
    )

    init = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": temp_password},
    )
    assert init["ChallengeName"] == "NEW_PASSWORD_REQUIRED", f"expected NEW_PASSWORD_REQUIRED, got {init.get('ChallengeName')}"
    session = init["Session"]

    # Error boundary: a bogus/garbage Session must be rejected before we consume the real one.
    # Real Cognito treats an unparseable Session as a code/response mismatch against the
    # challenge rather than an authorization failure, so it raises CodeMismatchException.
    code, message = _error(
        lambda: idp.admin_respond_to_auth_challenge(
            UserPoolId=pool_id,
            ClientId=client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": "NewPassw0rd!2"},
            Session="not-a-real-session-token",
        )
    )
    assert code == "CodeMismatchException", f"expected CodeMismatchException for bogus session, got {code}"
    expected_message = "Invalid code/session provided"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    resp = idp.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": "NewPassw0rd!2"},
        Session=session,
    )
    result = resp.get("AuthenticationResult")
    assert result is not None, f"expected AuthenticationResult on successful challenge, got {resp}"
    assert result.get("AccessToken"), "expected a non-empty AccessToken"

    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after setting permanent password, got {status}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_pool_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    return idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
