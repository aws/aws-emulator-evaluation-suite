"""admin-disable-enable-user-toggles-state."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "admin-disable-enable-user-toggles-state"
GROUP = 'user-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminDisableUser and AdminEnableUser flip the Enabled flag visible via AdminGetUser."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    baseline = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert baseline["Enabled"] is True, "expected a freshly created user to start Enabled=True"

    c.admin_disable_user(UserPoolId=pool_id, Username=username)
    disabled = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert disabled["Enabled"] is False, "expected Enabled=False after AdminDisableUser"

    c.admin_enable_user(UserPoolId=pool_id, Username=username)
    enabled = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert enabled["Enabled"] is True, "expected Enabled=True after AdminEnableUser"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
