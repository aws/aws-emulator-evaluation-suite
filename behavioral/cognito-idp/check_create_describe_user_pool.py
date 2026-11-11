"""create-describe-user-pool."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags


CHECK = "create-describe-user-pool"
GROUP = 'user-pool-lifecycle'
SERVICES = ['cognito-idp']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPool followed by an independent DescribeUserPool returns matching pool
    identity, a live (not canned) CreationDate, and the tags set at creation time."""
    c = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-behav-cip-pool-")
    before = datetime.now(timezone.utc)
    pool_id = c.create_user_pool(PoolName=name, UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    desc = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    after = datetime.now(timezone.utc)
    assert desc["Id"] == pool_id, f"expected id {pool_id}, got {desc['Id']}"
    assert desc["Name"] == name, f"expected name {name}, got {desc['Name']}"

    created = desc.get("CreationDate")
    assert created is not None, "expected CreationDate to be populated"
    window_start, window_end = before - timedelta(minutes=1), after + timedelta(minutes=1)
    assert window_start <= created <= window_end, (
        f"expected CreationDate in [{window_start}, {window_end}], got {created}"
    )

    pool_tags = desc.get("UserPoolTags") or {}
    assert pool_tags.get("sim2real:managed") == "true", (
        f"expected the independent describe read to reflect UserPoolTags set at creation, "
        f"got {pool_tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
