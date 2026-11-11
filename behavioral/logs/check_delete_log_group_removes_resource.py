"""delete-log-group-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-log-group-removes-resource"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLogGroup removes the group so it no longer appears in DescribeLogGroups."""
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-delete-")
    svc.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda _n=name: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=name: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    svc.delete_log_group(logGroupName=name)

    resp = svc.describe_log_groups(logGroupNamePrefix=name)
    names = [g["logGroupName"] for g in resp.get("logGroups", [])]
    assert name not in names, f"log group {name} still present after delete"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
