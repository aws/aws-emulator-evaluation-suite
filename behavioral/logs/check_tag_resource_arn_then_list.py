"""tag-resource-arn-then-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-arn-then-list"
GROUP = 'tagging'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource (ARN-based) tags are visible via ListTagsForResource."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-tagres-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    _arn_full = svc.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    arn = _arn_full[:-2] if _arn_full.endswith(":*") else _arn_full

    svc.tag_resource(resourceArn=arn, tags={"team": "behavioral"})

    resp = svc.list_tags_for_resource(resourceArn=arn)
    assert resp.get("tags") == {"team": "behavioral"}, (
        f"expected exactly {{'team': 'behavioral'}}, got {resp.get('tags')}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
