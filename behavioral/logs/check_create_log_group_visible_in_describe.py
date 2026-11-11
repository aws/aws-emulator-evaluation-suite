"""create-log-group-visible-in-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-log-group-visible-in-describe"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLogGroup makes the group immediately visible via DescribeLogGroups."""
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-create-")
    svc.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=name: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=name: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    resp = svc.describe_log_groups(logGroupNamePrefix=name)
    names = [g["logGroupName"] for g in resp.get("logGroups", [])]
    assert name in names, f"expected {name} in {names}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
