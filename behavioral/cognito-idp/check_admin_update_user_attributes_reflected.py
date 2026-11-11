"""admin-update-user-attributes-reflected."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "admin-update-user-attributes-reflected"
GROUP = 'user-attributes'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminUpdateUserAttributes changes are visible on the next AdminGetUser."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    c.admin_update_user_attributes(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": "behav-probe@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    attrs = {
        a["Name"]: a["Value"]
        for a in c.admin_get_user(UserPoolId=pool_id, Username=username)[
            "UserAttributes"
        ]
    }
    assert attrs.get("email") == "behav-probe@example.com", (
        f"expected email to be persisted, got {attrs.get('email')}"
    )
    assert attrs.get("email_verified") == "true", (
        f"expected email_verified 'true', got {attrs.get('email_verified')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
