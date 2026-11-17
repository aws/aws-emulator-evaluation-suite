"""cfn-deploy-neptune-cluster-backup-retention-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-neptune-cluster-backup-retention-out-of-range-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "neptune"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; two stacks fit an 1800 s cleanup budget


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


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


#: A Neptune cluster in its own VPC; ``BackupRetentionPeriod`` is the one property the two stacks
#: differ on.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: A Neptune cluster in a dedicated VPC.
Parameters:
  AzA: {Type: String}
  AzB: {Type: String}
  ClusterId: {Type: String}
  SubnetGroupName: {Type: String}
  BackupRetentionPeriod: {Type: Number}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.64.0.0/16
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.64.1.0/24
      AvailabilityZone: !Ref AzA
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.64.2.0/24
      AvailabilityZone: !Ref AzB
  SubnetGroup:
    Type: AWS::Neptune::DBSubnetGroup
    Properties:
      DBSubnetGroupName: !Ref SubnetGroupName
      DBSubnetGroupDescription: Subnet group for a Neptune cluster
      SubnetIds: [!Ref SubnetA, !Ref SubnetB]
  Cluster:
    Type: AWS::Neptune::DBCluster
    DeletionPolicy: Delete
    Properties:
      DBClusterIdentifier: !Ref ClusterId
      DBSubnetGroupName: !Ref SubnetGroup
      DeletionProtection: false
      BackupRetentionPeriod: !Ref BackupRetentionPeriod
Outputs:
  ClusterRef: {Value: !Ref Cluster}
"""

#: Neptune accepts 1-35; 0 is the legal neighbour's nearest out-of-range value.
_BAD_RETENTION = 0

_CREATE_TIMEOUT_S = 900.0
_REJECTED_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CloudFormation refuses a Neptune cluster naming a BackupRetentionPeriod outside 1-35
    before the cluster starts creating, and rolls the stack back; a positive control with every
    other property unchanged deploys and reads back through Neptune's own API.
    """
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    neptune = ctx.client("neptune")
    cfn = ctx.client("cloudformation")
    az_a, az_b = _two_usable_azs(ec2, neptune)

    good_id = ctx.unique_name("sim2real-nclg2-")
    good_stack = ctx.unique_name("sim2real-neptune-brpgood-")
    good_stack_id = _create_stack(ctx, cfn, good_stack, az_a, az_b, good_id,
                                  ctx.unique_name("sim2real-nsgg2-"), 5)
    good_status = wait_stack(cfn, good_stack_id, timeout_s=_CREATE_TIMEOUT_S)
    good_outputs = stack_outputs(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"positive control stack {good_stack!r} is {good_status!r}, expected CREATE_COMPLETE"
    )
    assert good_outputs["ClusterRef"] == good_id, (
        f"Ref of the control cluster is {good_outputs['ClusterRef']!r}, expected {good_id!r}"
    )
    control = neptune.describe_db_clusters(DBClusterIdentifier=good_id)["DBClusters"][0]
    assert control["Status"] == "available" and control["BackupRetentionPeriod"] == 5, (
        f"control cluster {good_id!r} is {control['Status']!r} with retention "
        f"{control['BackupRetentionPeriod']!r}, expected available at 5"
    )

    bad_id = ctx.unique_name("sim2real-nclb2-")
    bad_stack = ctx.unique_name("sim2real-neptune-brpbad-")
    bad_stack_id = _create_stack(ctx, cfn, bad_stack, az_a, az_b, bad_id,
                                 ctx.unique_name("sim2real-nsgb2-"), _BAD_RETENTION)
    bad_status = wait_stack(cfn, bad_stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} naming retention {_BAD_RETENTION!r} is {bad_status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )
    got = failed_reason(stack_events(cfn, bad_stack_id), bad_stack)
    assert got == _REJECTED_REASON, f"CREATE_FAILED reason {got!r}, expected {_REJECTED_REASON!r}"
    no_cluster_resources = [e for e in stack_events(cfn, bad_stack_id)
                            if e["LogicalResourceId"] == "Cluster"]
    assert no_cluster_resources == [], (
        f"the Cluster resource should never start creating, but saw {no_cluster_resources!r}"
    )
    expect_error(lambda: neptune.describe_db_clusters(DBClusterIdentifier=bad_id),
                 *("DBClusterNotFoundFault", f"DBCluster {bad_id} not found."))


def _create_stack(ctx, cfn, stack_name, az_a, az_b, cluster_id, subnet_group, retention
                   ) -> str:
    return create_stack(
        ctx, cfn, stack_name, _TEMPLATE,
        Parameters=[
            {"ParameterKey": "AzA", "ParameterValue": az_a},
            {"ParameterKey": "AzB", "ParameterValue": az_b},
            {"ParameterKey": "ClusterId", "ParameterValue": cluster_id},
            {"ParameterKey": "SubnetGroupName", "ParameterValue": subnet_group},
            {"ParameterKey": "BackupRetentionPeriod", "ParameterValue": str(retention)},
        ],
    )


def _two_usable_azs(ec2, neptune) -> tuple[str, str]:
    """Two AZs that both offer db.t3.medium for Neptune and are open for use."""
    offered = {
        z["Name"]
        for opt in neptune.describe_orderable_db_instance_options(
            Engine="neptune", DBInstanceClass="db.t3.medium")["OrderableDBInstanceOptions"]
        for z in opt["AvailabilityZones"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z.get("ZoneType", "availability-zone") == "availability-zone"
        and z.get("OptInStatus", "opt-in-not-required") == "opt-in-not-required"
    }
    usable = sorted(offered & available)
    assert len(usable) >= 2, (
        f"fewer than two usable AZs offer Neptune db.t3.medium: offered={sorted(offered)!r} "
        f"available={sorted(available)!r}"
    )
    return usable[0], usable[1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
