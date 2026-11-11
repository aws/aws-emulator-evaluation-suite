"""force-change-password-challenge."""
from __future__ import annotations

from behavioral_harness import tags


PASSWORD = "Sup3r-Secret-Passw0rd!"

CHECK = "force-change-password-challenge"
GROUP = 'auth-state-machine'
SERVICES = ['cognito-idp']

TEMP_PASSWORD = "T3mp0rary-Passw0rd!"

NEW_PASSWORD = "Rot4ted-Passw0rd!x"

ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FORCE_CHANGE_PASSWORD user gets NEW_PASSWORD_REQUIRED, not tokens."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS", TemporaryPassword=TEMP_PASSWORD)
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    resp = c.admin_initiate_auth(UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH", AuthParameters={"USERNAME": username, "PASSWORD": TEMP_PASSWORD})
    assert resp.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", (
        f"expected ChallengeName NEW_PASSWORD_REQUIRED, got {resp.get('ChallengeName')}"
    )
    assert "AuthenticationResult" not in resp, (
        "expected no AuthenticationResult while a challenge is outstanding"
    )
    assert resp.get("Session"), "expected a Session token to answer the challenge with"

    final = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": NEW_PASSWORD},
        Session=resp["Session"],
    )
    assert "AuthenticationResult" in final, (
        f"expected tokens after answering NEW_PASSWORD_REQUIRED, got {final.keys()}"
    )

    got = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["UserStatus"] == "CONFIRMED", (
        f"expected UserStatus CONFIRMED after password reset, got {got['UserStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
