"""cfn-rds-db-instance-monitoring-and-storage-properties-invalid-interval-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-db-instance-monitoring-and-storage-properties-invalid-interval-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds"]

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
_DELETE_BUDGET_S = 900.0
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, timeout_s, description, interval_s=5.0):
    """Call ``probe`` until ``done(result)``; return the result.

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
        time.sleep(interval_s)


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
        interval_s=2.0,
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
        StackName=name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": name}],
        Capabilities=["CAPABILITY_IAM"],
        **kw,
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_MONITORING_POLICY = {
    "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
_GOOD_INTERVAL = 60
_BAD_INTERVAL = 7  # not one of 0, 1, 5, 10, 15, 30, 60
# RDS's refusal while the new role's managed-policy attachment has not yet propagated.
_ROLE_NOT_READY = (
    "IAM role ARN value is invalid or does not include the required permissions for: "
    "ENHANCED_MONITORING (Service: Rds, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_MAX_ALLOCATED_STORAGE = 100


def _template(instance_id: str, subnet_group: str, monitoring_interval: int) -> str:
    """A standalone DB instance with its own Enhanced Monitoring role, DeletionPolicy Delete."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MonitoringRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "monitoring.rds.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [_MONITORING_POLICY],
                    },
                },
                "DBInstance": {
                    "Type": "AWS::RDS::DBInstance",
                    "DeletionPolicy": "Delete",
                    "Properties": {
                        "DBInstanceIdentifier": instance_id,
                        "Engine": "mysql",
                        "DBInstanceClass": "db.t4g.micro",
                        "AllocatedStorage": "20",
                        "MaxAllocatedStorage": _MAX_ALLOCATED_STORAGE,
                        "MasterUsername": "sim2realadmin",
                        "ManageMasterUserPassword": True,
                        "DBSubnetGroupName": subnet_group,
                        "BackupRetentionPeriod": 0,
                        "DeletionProtection": False,
                        "PubliclyAccessible": False,
                        "AutoMinorVersionUpgrade": False,
                        "MonitoringInterval": monitoring_interval,
                        "MonitoringRoleArn": {"Fn::GetAtt": ["MonitoringRole", "Arn"]},
                    },
                },
            },
            "Outputs": {
                "MonitoringRoleArnOut": {"Value": {"Fn::GetAtt": ["MonitoringRole", "Arn"]}},
            },
        }
    )


def _create_subnet_group(ctx, rds) -> str:
    """An RDS DB subnet group over the run's own shared network, covering >=2 AZs."""
    subnet_ids = ctx.network().subnet_ids
    assert len(subnet_ids) >= 2, f"the run's network has subnets in only {len(subnet_ids)} AZ(s)"
    name = ctx.unique_name("sim2real-rds-dbsg-")
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, name))
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real cfn instance property coverage",
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


def _create_stack_retrying_role_propagation(
    ctx, cf, rds, stack_name, instance_id, subnet_group, *, timeout_s=180.0, interval_s=15.0
):
    """Create the "good" stack, retrying a fresh create while RDS rejects the just-created
    Enhanced Monitoring role as not yet usable: IAM's attachment has not propagated.

    No condition the IAM API exposes is pollable, so the retry is bounded instead.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        stack_id = create_stack(
            ctx, cf, stack_name, _template(instance_id, subnet_group, _GOOD_INTERVAL)
        )
        status = wait_stack(ctx, cf, stack_id, timeout_s=1500.0)
        if status == "CREATE_COMPLETE":
            return stack_id
        events = stack_events(cf, stack_id)
        reason = (
            handler_reason(failed_reason(events, "DBInstance"), ctx.account)
            if any(
                lid == "DBInstance" and st == "CREATE_FAILED" for lid, st in decisive_rows(events)
            )
            else None
        )
        if reason != _ROLE_NOT_READY or time.monotonic() >= deadline:
            raise AssertionError(
                f"control stack {stack_id} settled at {status!r}: {decisive_rows(events)!r}"
            )
        delete_stack(ctx, cf, stack_id)
        time.sleep(interval_s)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A DB instance naming a MonitoringInterval outside 0|1|5|10|15|30|60 fails with RDS's exact
    message and leaves no instance; the same template with 60 deploys, and RDS reports
    MaxAllocatedStorage, AutoMinorVersionUpgrade, MonitoringInterval and the stack's role as declared."""
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx, rds)

    # ---- Negative: a MonitoringInterval outside the accepted set. ----
    bad_instance_id = ctx.unique_name("sim2real-rds-badmon-")
    bad_id = create_stack(
        ctx,
        cf,
        ctx.unique_name("sim2real-cfnrds-badmonstk-"),
        _template(bad_instance_id, subnet_group, _BAD_INTERVAL),
    )
    bad_status = wait_stack(ctx, cf, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"invalid-interval stack settled at {bad_status!r}: "
        f"{decisive_rows(stack_events(cf, bad_id))!r}"
    )
    got = handler_reason(
        failed_reason(stack_events(cf, bad_id), "DBInstance"), ctx.account, bad_instance_id
    )
    rejected = (
        "Invalid monitoring interval, please enter a value in [0, 1, 5, 10, 15, 30, 60] "
        "(Service: Rds, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "InvalidRequest",
    )
    assert got == rejected, (
        f"the DBInstance CREATE_FAILED reason was {got!r}, expected {rejected!r}"
    )
    bad_not_found = ("DBInstanceNotFound", f"DBInstance {bad_instance_id} not found.")
    expect_error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=bad_instance_id), *bad_not_found
    )
    delete_stack(ctx, cf, bad_id)

    # ---- Positive control: the same template, same subnet group, an accepted interval. ----
    good_instance_id = ctx.unique_name("sim2real-rds-goodmon-")
    good_id = _create_stack_retrying_role_propagation(
        ctx,
        cf,
        rds,
        ctx.unique_name("sim2real-cfnrds-goodmonstk-"),
        good_instance_id,
        subnet_group,
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=good_id)["Stacks"][0].get("Outputs", [])
    }

    instance = _poll(
        ctx,
        lambda: rds.describe_db_instances(DBInstanceIdentifier=good_instance_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        300.0,
        f"control instance {good_instance_id} status available",
    )
    partition = good_id.split(":")[1]
    role_arn = outputs["MonitoringRoleArnOut"]
    assert re.fullmatch(
        rf"arn:{partition}:iam::{ctx.account}:role/[A-Za-z0-9+=,.@_-]{{1,64}}", role_arn
    ), f"the stack's monitoring role ARN is {role_arn!r}"
    assert instance["MaxAllocatedStorage"] == _MAX_ALLOCATED_STORAGE, (
        f"MaxAllocatedStorage came back {instance.get('MaxAllocatedStorage')!r}, declared "
        f"{_MAX_ALLOCATED_STORAGE}"
    )
    assert instance["AutoMinorVersionUpgrade"] is False, (
        f"AutoMinorVersionUpgrade was declared False and came back "
        f"{instance.get('AutoMinorVersionUpgrade')!r}"
    )
    assert instance["MonitoringInterval"] == _GOOD_INTERVAL, (
        f"MonitoringInterval came back {instance.get('MonitoringInterval')!r}, declared "
        f"{_GOOD_INTERVAL}"
    )
    assert instance["MonitoringRoleArn"] == outputs["MonitoringRoleArnOut"], (
        f"MonitoringRoleArn came back {instance.get('MonitoringRoleArn')!r}, expected the "
        f"stack's own role {outputs['MonitoringRoleArnOut']!r}"
    )

    delete_stack(ctx, cf, good_id)
    good_not_found = ("DBInstanceNotFound", f"DBInstance {good_instance_id} not found.")
    expect_error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=good_instance_id), *good_not_found
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
