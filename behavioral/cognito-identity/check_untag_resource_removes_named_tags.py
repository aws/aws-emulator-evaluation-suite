"""untag-resource-removes-named-tags."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "untag-resource-removes-named-tags"
GROUP = 'pool-config'
SERVICES = ['cognito-identity']

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _identity_pool_arn(ctx, pool_id):
    """The cognito-identity pool ARN: arn:aws:cognito-identity:<region>:<account>:identitypool/<pool-id>."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cognito-identity:{ctx.region}:{account}:identitypool/{pool_id}"

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named keys, leaving other tags intact."""
    ev = ctx.client("cognito-identity")
    pool_id = _create_pool(ev, ctx, allow_unauth=True)
    arn = _identity_pool_arn(ctx, pool_id)

    ev.tag_resource(ResourceArn=arn, Tags={"keep": "yes", "drop": "no"})
    ev.untag_resource(ResourceArn=arn, TagKeys=["drop"])

    tags = ev.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("keep") == "yes", f"expected 'keep'='yes' to survive UntagResource, got {tags}"
    assert "drop" not in tags, f"expected 'drop' removed by UntagResource, still present: {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
