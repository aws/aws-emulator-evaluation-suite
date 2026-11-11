"""admin-respond-to-auth-challenge-rejects-bad-responses-without-spending-the-session."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-respond-to-auth-challenge-rejects-bad-responses-without-spending-the-session"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

TEMP_PASSWORD = "Sim2Real-Behav-Temp-1!"
NEW_PASSWORD = "Sim2Real-Behav-Pass-2!"
AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
NPR = "NEW_PASSWORD_REQUIRED"
_INVALID_SESSION = ("NotAuthorizedException", "Invalid session for the user.")
_WEAK_PASSWORD = ("InvalidPasswordException", "Password does not conform to policy: Password not long enough")
_NO_NEW_PASSWORD = ("InvalidParameterException", "Invalid attributes given, new password should be given with key NEW_PASSWORD")
_NO_USERNAME = ("InvalidParameterException", "Missing required parameter USERNAME")
_WRONG_CHALLENGE = ("CodeMismatchException", "Invalid code or auth state for the user.")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each bad response to a live NEW_PASSWORD_REQUIRED session is rejected with its own error, a user
    disabled mid-challenge is refused, and the session survives every rejection: the same Session
    then completes with all three tokens and no further challenge."""
    c = ctx.client("cognito-idp")
    pool_id = _pool(ctx, c)
    client_x = _client(ctx, c, pool_id)
    client_y = _client(ctx, c, pool_id)
    user_a, user_b, user_c = (_user(ctx, c, pool_id) for _ in range(3))

    started = _initiate(c, pool_id, client_x, user_a)
    assert started.get("ChallengeName") == NPR, f"expected {NPR}, got {started.get('ChallengeName')!r}"
    params = started["ChallengeParameters"]
    assert json.loads(params["requiredAttributes"]) == [], f"requiredAttributes is {params['requiredAttributes']!r}"
    assert params["USER_ID_FOR_SRP"] == user_a, f"USER_ID_FOR_SRP is {params['USER_ID_FOR_SRP']!r}"
    session = started["Session"]

    bad_responses = [
        (_WEAK_PASSWORD, client_x, NPR, {"USERNAME": user_a, "NEW_PASSWORD": "Ab1"}),
        (_NO_NEW_PASSWORD, client_x, NPR, {"USERNAME": user_a}),
        (_NO_USERNAME, client_x, NPR, {"NEW_PASSWORD": NEW_PASSWORD}),
        (_WRONG_CHALLENGE, client_x, "SOFTWARE_TOKEN_MFA", {"USERNAME": user_a, "SOFTWARE_TOKEN_MFA_CODE": "123456"}),
        (_INVALID_SESSION, client_y, NPR, {"USERNAME": user_a, "NEW_PASSWORD": NEW_PASSWORD}),
        (_INVALID_SESSION, client_x, NPR, {"USERNAME": user_b, "NEW_PASSWORD": NEW_PASSWORD}),
    ]
    for pair, client_id, name, responses in bad_responses:
        expect_error(lambda: _respond(c, pool_id, client_id, name, session, responses), *pair)
    assert _state(c, pool_id, user_b) == (True, "FORCE_CHANGE_PASSWORD"), "the cross-user response changed user B"

    started_c = _initiate(c, pool_id, client_x, user_c)
    assert started_c.get("ChallengeName") == NPR, f"user C: expected {NPR}, got {started_c.get('ChallengeName')!r}"
    assert _state(c, pool_id, user_c) == (True, "FORCE_CHANGE_PASSWORD"), "user C before the disable"
    c.admin_disable_user(UserPoolId=pool_id, Username=user_c)
    assert _state(c, pool_id, user_c) == (False, "FORCE_CHANGE_PASSWORD"), "user C after the disable"
    disabled_session = started_c["Session"]
    expect_error(lambda: _respond(c, pool_id, client_x, NPR, disabled_session,
                                  {"USERNAME": user_c, "NEW_PASSWORD": NEW_PASSWORD}), *_INVALID_SESSION)
    assert _state(c, pool_id, user_c) == (False, "FORCE_CHANGE_PASSWORD"), "the refused response changed user C"

    done = _respond(c, pool_id, client_x, NPR, session, {"USERNAME": user_a, "NEW_PASSWORD": NEW_PASSWORD})
    assert done.get("ChallengeParameters") == {}, f"ChallengeParameters after success has keys {sorted(done.get('ChallengeParameters') or {})!r}"
    assert "Session" not in done and "ChallengeName" not in done, f"success still carries a challenge: keys {sorted(done)!r}"
    result = done["AuthenticationResult"]
    assert result["TokenType"] == "Bearer", f"TokenType is {result['TokenType']!r}"
    assert result["ExpiresIn"] == 3600, f"ExpiresIn is {result['ExpiresIn']!r}"
    me = c.get_user(AccessToken=result["AccessToken"])
    assert me["Username"] == user_a, f"the completed session's access token resolved to {me.get('Username')!r}"
    refreshed = c.initiate_auth(
        ClientId=client_x, AuthFlow="REFRESH_TOKEN_AUTH", AuthParameters={"REFRESH_TOKEN": result["RefreshToken"]},
    )["AuthenticationResult"]
    me = c.get_user(AccessToken=refreshed["AccessToken"])
    assert me["Username"] == user_a, f"the refreshed access token resolved to {me.get('Username')!r}"
    signed_in = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_x, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user_a, "PASSWORD": NEW_PASSWORD},
    )["AuthenticationResult"]
    me = c.get_user(AccessToken=signed_in["AccessToken"])
    assert me["Username"] == user_a, f"the new password's access token resolved to {me.get('Username')!r}"
    assert _state(c, pool_id, user_a) == (True, "CONFIRMED"), "the completed challenge did not confirm user A"


def _initiate(c, pool_id, client_id, username):
    return c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": TEMP_PASSWORD},
    )


def _respond(c, pool_id, client_id, name, session, responses):
    return c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id, ClientId=client_id, ChallengeName=name, Session=session,
        ChallengeResponses=responses,
    )


def _state(c, pool_id, username):
    user = c.admin_get_user(UserPoolId=pool_id, Username=username)
    return user["Enabled"], user["UserStatus"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: keys {sorted(result)!r}")


def _pool(ctx, c):
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _client(ctx, c, pool_id):
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False, ExplicitAuthFlows=AUTH_FLOWS,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _user(ctx, c, pool_id):
    username = ctx.unique_name("sim2real-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword=TEMP_PASSWORD,
                        MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    return username


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
