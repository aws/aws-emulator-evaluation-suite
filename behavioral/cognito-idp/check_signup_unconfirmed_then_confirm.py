"""signup-unconfirmed-then-confirm."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "signup-unconfirmed-then-confirm"
GROUP = 'signup-state-machine'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"

USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SignUp yields UNCONFIRMED; AdminConfirmSignUp transitions the user to CONFIRMED."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(USER_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cipuser")

    resp = c.sign_up(ClientId=client_id, Username=username, Password=PASSWORD)
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    assert resp["UserConfirmed"] is False, (
        f"expected UserConfirmed False right after SignUp, got {resp['UserConfirmed']}"
    )
    assert resp.get("UserSub"), "expected a UserSub in the SignUp response"

    got = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["UserStatus"] == "UNCONFIRMED", (
        f"expected UserStatus UNCONFIRMED after SignUp, got {got['UserStatus']}"
    )

    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    after = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED", (
        f"expected UserStatus CONFIRMED after AdminConfirmSignUp, got {after['UserStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
