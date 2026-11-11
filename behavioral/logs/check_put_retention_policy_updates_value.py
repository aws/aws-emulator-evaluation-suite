"""put-retention-policy-updates-value."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-retention-policy-updates-value"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRetentionPolicy sets retentionInDays visible on the log group."""
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-retention-")
    svc.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=name: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=name: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    svc.put_retention_policy(logGroupName=name, retentionInDays=7)

    resp = svc.describe_log_groups(logGroupNamePrefix=name)
    groups = {g["logGroupName"]: g for g in resp.get("logGroups", [])}
    assert groups[name].get("retentionInDays") == 7, groups.get(name)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
