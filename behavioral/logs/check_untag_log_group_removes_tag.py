"""untag-log-group-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-log-group-removes-tag"
GROUP = 'tagging'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagLogGroup removes a previously-set tag."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-untag-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.tag_log_group(logGroupName=group, tags={"env": "behavioral-check", "keep": "yes"})

    before = svc.list_tags_log_group(logGroupName=group).get("tags", {})
    assert before.get("env") == "behavioral-check", before
    assert before.get("keep") == "yes", before

    svc.untag_log_group(logGroupName=group, tags=["env"])

    after = svc.list_tags_log_group(logGroupName=group).get("tags", {})
    assert "env" not in after, after
    assert after.get("keep") == "yes", (
        "untagging one key must not remove unrelated tags",
        after,
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
