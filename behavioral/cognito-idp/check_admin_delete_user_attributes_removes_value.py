"""admin-delete-user-attributes-removes-value."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "admin-delete-user-attributes-removes-value"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminDeleteUserAttributes removes an attribute value such that a subsequent
    AdminGetUser no longer returns it."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "nickname", "Value": "Buddy"},
            {"Name": "profile", "Value": "https://example.com/profile"},
        ],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))

    before = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert before.get("nickname") == "Buddy", f"expected nickname 'Buddy' before delete, got {before.get('nickname')!r}"
    assert before.get("profile") == "https://example.com/profile", (
        f"expected profile set before delete, got {before.get('profile')!r}"
    )

    idp.admin_delete_user_attributes(
        UserPoolId=pool_id, Username=username, UserAttributeNames=["nickname"]
    )

    after = {
        a["Name"]: a["Value"]
        for a in idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserAttributes"]
    }
    assert "nickname" not in after, f"expected nickname removed, still present: {after.get('nickname')!r}"
    assert after.get("profile") == "https://example.com/profile", "unrelated attributes must survive"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
