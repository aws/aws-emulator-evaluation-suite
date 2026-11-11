"""create-group-in-nonexistent-pool-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-in-nonexistent-pool-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroup succeeds on a real pool and is refused on an unknown pool id with
    ResourceNotFoundException "User pool <id> does not exist." (exact message)."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    group_name = ctx.unique_name("sim2real-behav-cip-group-")
    created = c.create_group(UserPoolId=pool_id, GroupName=group_name)["Group"]
    assert created["GroupName"] == group_name, (
        f"expected positive control to create {group_name!r}, got {created.get('GroupName')!r}"
    )

    bogus_id = f"{ctx.region}_" + uuid.uuid4().hex[:9]
    try:
        c.create_group(UserPoolId=bogus_id, GroupName=ctx.unique_name("sim2real-behav-cip-group-"))
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown pool, got {code}"
    )
    assert message == f"User pool {bogus_id} does not exist.", (
        f"expected the exact unknown-pool message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
