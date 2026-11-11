"""auth-challenge-session-sequencing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auth-challenge-session-sequencing"
GROUP = 'auth-state-machine'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _err(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises AssertionError, so an emulator accepting what AWS refuses never reads as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    kwargs.setdefault("DeletionProtection", "INACTIVE")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


def _create_user(ctx, c, pool_id, username, temp_password):
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=temp_password,
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))


def _admin_login(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


def _user_login(c, client_id, username, password):
    resp = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Answering NEW_PASSWORD_REQUIRED via AdminRespondToAuthChallenge returns access, ID and refresh tokens and
    confirms the user; the answered Session is then refused there and on RespondToAuthChallenge with
    NotAuthorizedException and the exact used-once message, while a second Session minted earlier completes once."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    temp_password = "Temp0rar1Pass!"

    # --- Admin surface: AdminInitiateAuth / AdminRespondToAuthChallenge ---
    admin_username = ctx.unique_name("sim2real-behav-cip-admin-chal-")
    _create_user(ctx, c, pool_id, admin_username, temp_password)

    admin_challenge = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": admin_username, "PASSWORD": temp_password},
    )
    assert admin_challenge["ChallengeName"] == "NEW_PASSWORD_REQUIRED", admin_challenge.get(
        "ChallengeName"
    )
    admin_session1 = admin_challenge["Session"]

    new_password = "PostChallengePassw0rd!"
    completed = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=admin_session1,
        ChallengeResponses={"USERNAME": admin_username, "NEW_PASSWORD": new_password},
    )
    assert "AuthenticationResult" in completed, completed
    for key in ("AccessToken", "IdToken", "RefreshToken"):
        assert completed["AuthenticationResult"].get(key), f"missing {key} in AuthenticationResult"
    status = c.admin_get_user(UserPoolId=pool_id, Username=admin_username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after the challenge is answered, got {status}"

    # BOUNDARY: replaying the SAME (already-consumed) session token must be rejected -- a session
    # is single-use, tied to the specific challenge round trip that issued it -- with the specific
    # state-conflict code, not any error whatsoever.
    code_replay, code_replay_msg = _err(
        lambda: c.admin_respond_to_auth_challenge(
            UserPoolId=pool_id,
            ClientId=client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=admin_session1,
            ChallengeResponses={"USERNAME": admin_username, "NEW_PASSWORD": "AnotherPassw0rd1!"},
        )
    )
    assert code_replay == "NotAuthorizedException", (
        f"expected AdminRespondToAuthChallenge to reject a replayed/consumed Session token with "
        f"NotAuthorizedException, got {code_replay}"
    )
    assert code_replay_msg == 'Invalid session for the user, session can only be used once.', f"expected the exact {code_replay} message, got {code_replay_msg!r}"

    relogin = _admin_login(c, pool_id, client_id, admin_username, new_password)
    assert relogin["AccessToken"], "expected the originally-set new password to still work"

    # --- Self-service surface: InitiateAuth / RespondToAuthChallenge ---
    self_username = ctx.unique_name("sim2real-behav-cip-self-chal-")
    _create_user(ctx, c, pool_id, self_username, temp_password)

    def initiate():
        resp = c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": self_username, "PASSWORD": temp_password},
        )
        assert resp["ChallengeName"] == "NEW_PASSWORD_REQUIRED", resp.get("ChallengeName")
        return resp["Session"]

    # Two independent InitiateAuth calls mint two DISTINCT session tokens for the same outstanding
    # challenge; each remains independently completable until its own expiry. What sequencing
    # strictly enforces is that a session becomes permanently unusable once IT ITSELF is consumed.
    session_a = initiate()
    session_b = initiate()
    assert session_a != session_b, "expected two independent InitiateAuth calls to mint distinct sessions"

    self_new_password = "SelfPostChallengePassw0rd!"
    completed_a = c.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=session_a,
        ChallengeResponses={"USERNAME": self_username, "NEW_PASSWORD": self_new_password},
    )
    assert "AuthenticationResult" in completed_a, completed_a

    # BOUNDARY: replaying the spent session_a must be rejected with the specific state-conflict
    # code, not any error whatsoever.
    code_replay_self, code_replay_self_msg = _err(
        lambda: c.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=session_a,
            ChallengeResponses={"USERNAME": self_username, "NEW_PASSWORD": "YetAnotherPassw0rd1!"},
        )
    )
    assert code_replay_self == "NotAuthorizedException", (
        f"expected RespondToAuthChallenge to reject a replayed/consumed Session token with "
        f"NotAuthorizedException, got {code_replay_self}"
    )
    assert code_replay_self_msg == 'Invalid session for the user, session can only be used once.', f"expected the exact {code_replay_self} message, got {code_replay_self_msg!r}"

    final_login = _user_login(c, client_id, self_username, self_new_password)
    assert final_login["AccessToken"], "expected the password set via session_a to still work"

    # session_b, though minted before session_a was consumed, was ITSELF never consumed -- so it
    # remains independently valid and can still complete the challenge, again resetting the password.
    completed_b = c.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=session_b,
        ChallengeResponses={"USERNAME": self_username, "NEW_PASSWORD": self_new_password},
    )
    assert "AuthenticationResult" in completed_b, completed_b

    # And, symmetrically, session_b is spent too: replaying IT must fail with the same
    # specific code.
    code_replay_b, code_replay_b_msg = _err(
        lambda: c.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=session_b,
            ChallengeResponses={"USERNAME": self_username, "NEW_PASSWORD": "OneMorePassw0rd1!"},
        )
    )
    assert code_replay_b == "NotAuthorizedException", (
        f"expected RespondToAuthChallenge to reject session_b once it too has been consumed "
        f"with NotAuthorizedException, got {code_replay_b}"
    )
    assert code_replay_b_msg == 'Invalid session for the user, session can only be used once.', f"expected the exact {code_replay_b} message, got {code_replay_b_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
