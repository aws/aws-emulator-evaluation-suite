"""admin-set-user-password-updates-status."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "admin-set-user-password-updates-status"
GROUP = 'user-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminSetUserPassword with Permanent=True transitions status away from FORCE_CHANGE_PASSWORD."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    # positive control: a fresh admin-created user starts in FORCE_CHANGE_PASSWORD, so the
    # terminal CONFIRMED below is a real transition and not a status the target always reports.
    before = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "FORCE_CHANGE_PASSWORD", (
        f"expected UserStatus FORCE_CHANGE_PASSWORD before a permanent password is set, got {before['UserStatus']}"
    )

    c.admin_set_user_password(
        UserPoolId=pool_id,
        Username=username,
        Password="Sup3r-Secret-Passw0rd!",
        Permanent=True,
    )
    got = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["UserStatus"] == "CONFIRMED", (
        f"expected UserStatus CONFIRMED after permanent password set, got {got['UserStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
