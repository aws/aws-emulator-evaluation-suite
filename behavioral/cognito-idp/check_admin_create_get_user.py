"""admin-create-get-user."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "admin-create-get-user"
GROUP = 'user-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminCreateUser followed by AdminGetUser returns the expected initial state."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    got = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["Username"] == username, f"expected AdminGetUser to echo Username {username!r}, got {got['Username']!r}"
    assert got["Enabled"] is True, f"expected new user to be Enabled, got {got['Enabled']}"
    assert got["UserStatus"] == "FORCE_CHANGE_PASSWORD", (
        f"expected initial UserStatus FORCE_CHANGE_PASSWORD, got {got['UserStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
