"""cfn-rds-instance-snapshot-provisioning-and-teardown."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-instance-snapshot-provisioning-and-teardown"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
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
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
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


def _poll_status(describe, extract_status, *, ok: set, bad: set, timeout_s: float,
                  interval_s: float = 5.0, description: str):
    """Poll ``describe()`` until ``extract_status`` is in ``ok``; raise on ``bad`` or timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = describe()
        status = extract_status(result)
        if status in ok:
            return result
        if status in bad:
            raise AssertionError(f"{description} reached {status!r}, expected one of {sorted(ok)}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} still {status!r} after {timeout_s}s, expected one of {sorted(ok)}"
            )
        time.sleep(interval_s)


def _template(instance_id: str, snapshot_id: str, subnet_group: str) -> dict:
    """An instance and a manual snapshot of it."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DBInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBInstanceIdentifier": instance_id,
                    "Engine": "mysql",
                    "DBInstanceClass": "db.t4g.micro",
                    "AllocatedStorage": "20",
                    "MasterUsername": "sim2realadmin",
                    "ManageMasterUserPassword": True,
                    "DBSubnetGroupName": subnet_group,
                    "BackupRetentionPeriod": 0,
                    "DeletionProtection": False,
                    "PubliclyAccessible": False,
                },
            },
            "DBSnapshot": {
                "Type": "AWS::RDS::DBSnapshot",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBInstanceIdentifier": {"Ref": "DBInstance"},
                    "DBSnapshotIdentifier": snapshot_id,
                },
            },
        },
        "Outputs": {
            "DBInstanceRef": {"Value": {"Ref": "DBInstance"}},
            "DBInstanceArn": {"Value": {"Fn::GetAtt": ["DBInstance", "DBInstanceArn"]}},
            "DBInstanceEndpointAddress": {
                "Value": {"Fn::GetAtt": ["DBInstance", "Endpoint.Address"]}
            },
            "DBInstanceEndpointPort": {"Value": {"Fn::GetAtt": ["DBInstance", "Endpoint.Port"]}},
            "DBSnapshotRef": {"Value": {"Ref": "DBSnapshot"}},
            "DBSnapshotArn": {"Value": {"Fn::GetAtt": ["DBSnapshot", "DBSnapshotArn"]}},
        },
    }


def _delete_subnet_group(rds, name):
    """Delete the subnet group; only its own not-found fault means it never existed."""
    try:
        rds.delete_db_subnet_group(DBSubnetGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSubnetGroupNotFoundFault":
            raise


def _create_subnet_group(ctx, rds) -> str:
    """An RDS DB subnet group over the run's own shared network, covering >=2 AZs."""
    subnet_ids = ctx.network().subnet_ids
    assert len(subnet_ids) >= 2, f"the run's network has subnets in only {len(subnet_ids)} AZ(s)"
    name = ctx.unique_name("sim2real-rds-dbsg-")
    ctx.on_cleanup(lambda: _delete_subnet_group(rds, name))
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real cfn provisioning check",
        SubnetIds=subnet_ids[:2],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    return name


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::RDS::DBInstance and AWS::RDS::DBSnapshot are real RDS
    resources: Ref/GetAtt and the template's properties match RDS's own description, and both
    resources are gone from RDS once the stack is deleted.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbsnapshot.html
    """
    cf = ctx.client("cloudformation")
    rds = ctx.client("rds")

    subnet_group = _create_subnet_group(ctx, rds)
    instance_id = ctx.unique_name("sim2real-rds-inst-")
    snapshot_id = ctx.unique_name("sim2real-rds-snap-")

    template = json.dumps(_template(instance_id, snapshot_id, subnet_group))
    stack_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfn-rds-"), template)
    status = wait_stack(cf, stack_id, timeout_s=1500.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)

    # ---- Ref: the DB instance name ----
    assert outputs["DBInstanceRef"] == instance_id, (
        f"Ref on the DBInstance returned {outputs['DBInstanceRef']!r}, expected the "
        f"DBInstanceIdentifier {instance_id!r}"
    )

    instance = _poll_status(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"],
        ok={"available"},
        bad={"failed", "incompatible-parameters", "incompatible-network"},
        timeout_s=900.0,
        description=f"DB instance {instance_id}",
    )
    assert instance["Engine"] == "mysql", f"RDS reports engine {instance['Engine']!r}, expected 'mysql'"
    assert instance["DBInstanceClass"] == "db.t4g.micro", (
        f"RDS reports class {instance['DBInstanceClass']!r}, expected 'db.t4g.micro'"
    )
    assert instance["AllocatedStorage"] == 20, (
        f"RDS reports {instance['AllocatedStorage']!r} GiB allocated, expected 20 (the template's value)"
    )
    got = (instance["DBSubnetGroup"]["DBSubnetGroupName"], instance["MasterUsername"],
           instance["BackupRetentionPeriod"], instance["DeletionProtection"],
           instance["PubliclyAccessible"])
    want = (subnet_group, "sim2realadmin", 0, False, False)
    assert got == want, (
        f"RDS reports (DBSubnetGroupName, admin user name, BackupRetentionPeriod, "
        f"DeletionProtection, PubliclyAccessible) {got!r}, expected the template's {want!r}"
    )
    # With a managed password, RDS keeps the password in a secret it reports on the instance.
    assert "SecretArn" in instance.get("MasterUserSecret", {}), (
        f"expected an RDS-managed admin-user secret, RDS reports "
        f"{instance.get('MasterUserSecret')!r}"
    )
    # ---- Fn::GetAtt outputs equal RDS's own values ----
    assert outputs["DBInstanceArn"] == instance["DBInstanceArn"], (
        f"stack Output DBInstanceArn {outputs['DBInstanceArn']!r} != RDS's own "
        f"{instance['DBInstanceArn']!r}"
    )
    assert outputs["DBInstanceEndpointAddress"] == instance["Endpoint"]["Address"], (
        f"stack Output endpoint address {outputs['DBInstanceEndpointAddress']!r} != RDS's own "
        f"{instance['Endpoint']['Address']!r}"
    )
    assert int(outputs["DBInstanceEndpointPort"]) == instance["Endpoint"]["Port"], (
        f"stack Output endpoint port {outputs['DBInstanceEndpointPort']!r} != RDS's own "
        f"{instance['Endpoint']['Port']!r}"
    )

    snapshot = _poll_status(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0],
        lambda s: s["Status"],
        ok={"available"},
        bad={"failed"},
        timeout_s=900.0,
        description=f"DB snapshot {snapshot_id}",
    )
    # ---- the property the template set (DBInstanceIdentifier) reads back from RDS ----
    assert snapshot["DBInstanceIdentifier"] == instance_id, (
        f"RDS reports the snapshot's source instance as {snapshot['DBInstanceIdentifier']!r}, "
        f"expected {instance_id!r} (the template's DBInstanceIdentifier)"
    )
    # ---- Ref on DBSnapshot: the snapshot ARN ----
    assert outputs["DBSnapshotRef"] == snapshot["DBSnapshotArn"], (
        f"Ref on the DBSnapshot returned {outputs['DBSnapshotRef']!r}, expected RDS's own ARN "
        f"{snapshot['DBSnapshotArn']!r}"
    )
    assert outputs["DBSnapshotArn"] == snapshot["DBSnapshotArn"], (
        f"stack Output DBSnapshotArn {outputs['DBSnapshotArn']!r} != RDS's own "
        f"{snapshot['DBSnapshotArn']!r}"
    )

    # ---- delete the stack, then prove both resources are gone from RDS ----
    # An instance delete outlasts delete_stack's 600 s budget: delete by StackId and wait longer.
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=1200.0)
    assert status == "DELETE_COMPLETE", (
        f"stack delete ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    instance_not_found = ("DBInstanceNotFound", f"DBInstance {instance_id} not found.")
    expect_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id), *instance_not_found)

    snapshot_not_found = ("DBSnapshotNotFound", f"DBSnapshot not found: {snapshot_id}")
    expect_error(lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id), *snapshot_not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
