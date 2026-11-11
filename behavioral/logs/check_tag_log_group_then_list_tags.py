"""tag-log-group-then-list-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-log-group-then-list-tags"
GROUP = 'tagging'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagLogGroup tags are visible via ListTagsLogGroup."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-tag-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    applied = {"env": "behavioral-check"}
    svc.tag_log_group(logGroupName=group, tags=applied)

    resp = svc.list_tags_log_group(logGroupName=group)
    assert resp["tags"] == applied, f"expected {applied}, got {resp['tags']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
