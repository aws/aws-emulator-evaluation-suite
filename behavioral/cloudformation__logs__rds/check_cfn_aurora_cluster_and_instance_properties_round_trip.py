"""cfn-aurora-cluster-and-instance-properties-round-trip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-aurora-cluster-and-instance-properties-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs", "rds"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
# Create, settle and delete together stay within 30 minutes.
_CREATE_BUDGET_S = 1100.0
_SETTLE_BUDGET_S = 120.0
_DELETE_BUDGET_S = 580.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, timeout_s, description):
    """Call ``probe`` every 5 s until ``done(result)``; return the result.

    A spent run budget raises TimeoutError (not graded); the wait's own deadline fails the check.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s:.0f}s: {last!r}")
        time.sleep(5)


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    return _poll(
        ctx,
        lambda: cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"],
        lambda status: status in terminal,
        timeout_s,
        f"stack {stack_id} reaching one of {sorted(terminal)}",
    )


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(ctx, cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        ctx, cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(ctx, cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(ctx, cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(ctx, cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    rows = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cf.describe_stack_events(**kwargs)
        rows.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return rows[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_BACKUP_WINDOW = "09:00-09:30"
_MAINTENANCE_WINDOW = "wed:05:00-wed:05:30"
_LOG_EXPORTS = ["error", "general"]
_PROMOTION_TIER = 2


def _template(cluster_id: str, instance_id: str, subnet_group: str) -> str:
    """An Aurora MySQL DBCluster with one member DBInstance, both DeletionPolicy Delete."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "DBCluster": {
                    "Type": "AWS::RDS::DBCluster",
                    "DeletionPolicy": "Delete",
                    "Properties": {
                        "DBClusterIdentifier": cluster_id,
                        "Engine": "aurora-mysql",
                        "MasterUsername": "sim2realadmin",
                        "ManageMasterUserPassword": True,
                        "DBSubnetGroupName": subnet_group,
                        "BackupRetentionPeriod": 1,
                        "PreferredBackupWindow": _BACKUP_WINDOW,
                        "PreferredMaintenanceWindow": _MAINTENANCE_WINDOW,
                        "EnableIAMDatabaseAuthentication": True,
                        "EnableCloudwatchLogsExports": _LOG_EXPORTS,
                        "DeletionProtection": False,
                    },
                },
                "DBInstance": {
                    "Type": "AWS::RDS::DBInstance",
                    "DeletionPolicy": "Delete",
                    "Properties": {
                        "DBInstanceIdentifier": instance_id,
                        "Engine": "aurora-mysql",
                        "DBInstanceClass": "db.t3.medium",
                        "DBClusterIdentifier": {"Ref": "DBCluster"},
                        "PromotionTier": _PROMOTION_TIER,
                    },
                },
            },
        }
    )


def _delete_log_groups(logs, cluster_id: str) -> None:
    """Delete the cluster's exported-log groups; only the exact not-found means already gone."""
    for kind in _LOG_EXPORTS:
        try:
            logs.delete_log_group(logGroupName=f"/aws/rds/cluster/{cluster_id}/{kind}")
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) != (
                "ResourceNotFoundException",
                "The specified log group does not exist.",
            ):
                raise


def _create_subnet_group(ctx, rds) -> str:
    """An RDS DB subnet group over the run's own shared network, covering >=2 AZs."""
    subnet_ids = ctx.network().subnet_ids
    assert len(subnet_ids) >= 2, f"the run's network has subnets in only {len(subnet_ids)} AZ(s)"
    name = ctx.unique_name("sim2real-rds-dbsg-")
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, name))
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real cfn cluster property coverage",
        SubnetIds=subnet_ids[:2],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    return name


def _delete_subnet_group(rds, name):
    """Delete the subnet group; only its own not-found fault means it never existed."""
    try:
        rds.delete_db_subnet_group(DBSubnetGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSubnetGroupNotFoundFault":
            raise


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Aurora DBCluster and its member DBInstance read back exactly what the
    template declared (log exports, IAM database authentication, backup and maintenance windows,
    promotion tier), and deleting the stack removes both."""
    cf = ctx.client("cloudformation")
    logs = ctx.client("logs")
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx, rds)

    cluster_id = ctx.unique_name("sim2real-rds-aurclu-")
    instance_id = ctx.unique_name("sim2real-rds-aurinst-")
    # The exported-log groups outlive the cluster; they go after the stack's own teardown.
    ctx.on_cleanup(lambda: _delete_log_groups(logs, cluster_id))
    stack_id = create_stack(
        ctx,
        cf,
        ctx.unique_name("sim2real-cfnrds-aurstk-"),
        _template(cluster_id, instance_id, subnet_group),
    )
    status = wait_stack(ctx, cf, stack_id, timeout_s=_CREATE_BUDGET_S)
    assert status == "CREATE_COMPLETE", (
        f"stack settled at {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )

    cluster = _poll(
        ctx,
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c["Status"] == "available",
        _SETTLE_BUDGET_S,
        f"cluster {cluster_id} status available",
    )
    assert sorted(cluster["EnabledCloudwatchLogsExports"]) == sorted(_LOG_EXPORTS), (
        f"EnabledCloudwatchLogsExports came back {cluster.get('EnabledCloudwatchLogsExports')!r}, "
        f"declared {_LOG_EXPORTS!r}"
    )
    assert cluster["IAMDatabaseAuthenticationEnabled"] is True, (
        f"EnableIAMDatabaseAuthentication was declared True and came back "
        f"{cluster.get('IAMDatabaseAuthenticationEnabled')!r}"
    )
    assert cluster["PreferredBackupWindow"] == _BACKUP_WINDOW, (
        f"PreferredBackupWindow came back {cluster.get('PreferredBackupWindow')!r}, declared "
        f"{_BACKUP_WINDOW!r}"
    )
    assert cluster["PreferredMaintenanceWindow"] == _MAINTENANCE_WINDOW, (
        f"PreferredMaintenanceWindow came back {cluster.get('PreferredMaintenanceWindow')!r}, "
        f"declared {_MAINTENANCE_WINDOW!r}"
    )

    instance = _poll(
        ctx,
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        _SETTLE_BUDGET_S,
        f"instance {instance_id} status available",
    )
    assert instance["DBClusterIdentifier"] == cluster_id, (
        f"member instance reports cluster {instance['DBClusterIdentifier']!r}, expected "
        f"{cluster_id!r}"
    )
    assert instance["PromotionTier"] == _PROMOTION_TIER, (
        f"PromotionTier came back {instance.get('PromotionTier')!r}, declared {_PROMOTION_TIER}"
    )

    delete_stack(ctx, cf, stack_id)
    cluster_gone = ("DBClusterNotFoundFault", f"DBCluster {cluster_id} not found.")
    expect_error(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id), *cluster_gone)
    instance_gone = ("DBInstanceNotFound", f"DBInstance {instance_id} not found.")
    expect_error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id), *instance_gone
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
