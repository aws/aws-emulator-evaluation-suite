"""cfn-deploy-neptune-cluster-two-instances-writer-reader-and-tags."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-neptune-cluster-two-instances-writer-reader-and-tags"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "neptune"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 1500.0  # one stack with two instances to tear down sequentially


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


def delete_stack_named(cf, name, stack_id=None, timeout_s=_DELETE_BUDGET_S):
    """Delete by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports. Raises unless DELETE_COMPLETE.
    """
    deadline = time.monotonic() + timeout_s
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
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


#: A private VPC, a two-AZ subnet group, a tagged Neptune cluster and two instances in it.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: A tagged Neptune cluster with two instances in a dedicated VPC.
Parameters:
  AzA: {Type: String}
  AzB: {Type: String}
  ClusterId: {Type: String}
  InstanceAId: {Type: String}
  InstanceBId: {Type: String}
  SubnetGroupName: {Type: String}
  TagValue: {Type: String}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.63.0.0/16
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.63.1.0/24
      AvailabilityZone: !Ref AzA
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.63.2.0/24
      AvailabilityZone: !Ref AzB
  ClusterSg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Neptune cluster security group
      VpcId: !Ref Vpc
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
      VpcSecurityGroupIds: [!Ref ClusterSg]
      DeletionProtection: false
      Tags:
        - Key: Project
          Value: !Ref TagValue
  InstanceA:
    Type: AWS::Neptune::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceIdentifier: !Ref InstanceAId
      DBInstanceClass: db.t3.medium
      DBClusterIdentifier: !Ref Cluster
  InstanceB:
    Type: AWS::Neptune::DBInstance
    DeletionPolicy: Delete
    DependsOn: InstanceA
    Properties:
      DBInstanceIdentifier: !Ref InstanceBId
      DBInstanceClass: db.t3.medium
      DBClusterIdentifier: !Ref Cluster
Outputs:
  ClusterRef: {Value: !Ref Cluster}
  ClusterArn: {Value: !GetAtt Cluster.ClusterResourceId}
  ClusterPort: {Value: !GetAtt Cluster.Port}
  InstanceARef: {Value: !Ref InstanceA}
  InstanceBRef: {Value: !Ref InstanceB}
"""

#: A cluster is a few minutes; two instances inside it several more, mostly in parallel.
_CREATE_TIMEOUT_S = 1800.0
#: The create and the in-check stack delete share one deadline; the delete of two instances
#: can take longer than 600 s.
_RUN_BUDGET_S = 2640.0


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed Neptune cluster with two instances reports exactly one of them
    as the writer, both at the cluster's own port and the template's instance class, and the
    cluster's tags carry the template's tag plus CloudFormation's aws:cloudformation:* tags.
    """
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    neptune = ctx.client("neptune")
    cfn = ctx.client("cloudformation")

    az_a, az_b = _two_usable_azs(ec2, neptune)
    cluster_id = ctx.unique_name("sim2real-ncl2-")
    instance_a_id = ctx.unique_name("sim2real-nina-")
    instance_b_id = ctx.unique_name("sim2real-ninb-")
    subnet_group = ctx.unique_name("sim2real-nsg2-")
    stack_name = ctx.unique_name("sim2real-neptune-2inst-")
    tag_value = ctx.unique_name("sim2real-ncl2-tag-")

    deadline = time.monotonic() + _RUN_BUDGET_S
    stack_id = create_stack(
        ctx, cfn, stack_name, _TEMPLATE,
        Parameters=[
            {"ParameterKey": "AzA", "ParameterValue": az_a},
            {"ParameterKey": "AzB", "ParameterValue": az_b},
            {"ParameterKey": "ClusterId", "ParameterValue": cluster_id},
            {"ParameterKey": "InstanceAId", "ParameterValue": instance_a_id},
            {"ParameterKey": "InstanceBId", "ParameterValue": instance_b_id},
            {"ParameterKey": "SubnetGroupName", "ParameterValue": subnet_group},
            {"ParameterKey": "TagValue", "ParameterValue": tag_value},
        ],
    )
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    assert outputs["ClusterRef"] == cluster_id, (
        f"Ref of the cluster is {outputs['ClusterRef']!r}, expected {cluster_id!r}"
    )
    assert outputs["InstanceARef"] == instance_a_id, outputs["InstanceARef"]
    assert outputs["InstanceBRef"] == instance_b_id, outputs["InstanceBRef"]

    cluster = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["Status"] == "available", f"cluster {cluster_id!r} is {cluster['Status']!r}"
    cluster_arn = cluster["DBClusterArn"]

    members = cluster["DBClusterMembers"]
    assert len(members) == 2, f"DescribeDBClusters reports {len(members)} member(s): {members!r}"
    member_ids = sorted(m["DBInstanceIdentifier"] for m in members)
    assert member_ids == sorted([instance_a_id, instance_b_id]), (
        f"cluster members {member_ids!r}, expected [{instance_a_id!r}, {instance_b_id!r}]"
    )
    writers = [m for m in members if m["IsClusterWriter"]]
    assert len(writers) == 1, f"exactly one member should be the writer, got {members!r}"
    readers = [m for m in members if not m["IsClusterWriter"]]
    assert len(readers) == 1, f"exactly one member should not be the writer, got {members!r}"

    cluster_port = cluster["Port"]
    instance_a = neptune.describe_db_instances(DBInstanceIdentifier=instance_a_id)["DBInstances"][0]
    instance_b = neptune.describe_db_instances(DBInstanceIdentifier=instance_b_id)["DBInstances"][0]
    for inst, inst_id in ((instance_a, instance_a_id), (instance_b, instance_b_id)):
        assert inst["Endpoint"]["Port"] == cluster_port, (
            f"instance {inst_id!r} reports port {inst['Endpoint']['Port']!r}, expected the "
            f"cluster's own port {cluster_port!r}"
        )
        assert inst["DBInstanceClass"] == "db.t3.medium", (
            f"instance {inst_id!r} reports class {inst['DBInstanceClass']!r}, expected the "
            f"template's db.t3.medium"
        )
        assert inst["DBClusterIdentifier"] == cluster_id, inst["DBClusterIdentifier"]

    cluster_tags = {t["Key"]: t["Value"] for t in neptune.list_tags_for_resource(
        ResourceName=cluster_arn)["TagList"]}
    want_tags = {
        "Project": tag_value,
        "sim2real": stack_name,
        "aws:cloudformation:stack-name": stack_name,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:logical-id": "Cluster",
    }
    assert cluster_tags == want_tags, (
        f"ListTagsForResource on the cluster returns {cluster_tags!r}, expected the template's "
        f"tag plus CloudFormation's own aws:cloudformation:* tags {want_tags!r}"
    )

    # The stack delete removes both instances and the cluster.
    delete_stack_named(cfn, stack_name, stack_id, timeout_s=deadline - time.monotonic())
    instance_a_gone = ("DBInstanceNotFound", f"DBInstance {instance_a_id} not found.")
    instance_b_gone = ("DBInstanceNotFound", f"DBInstance {instance_b_id} not found.")
    cluster_gone = ("DBClusterNotFoundFault", f"DBCluster {cluster_id} not found.")
    expect_error(lambda: neptune.describe_db_instances(DBInstanceIdentifier=instance_a_id),
                 *instance_a_gone)
    expect_error(lambda: neptune.describe_db_instances(DBInstanceIdentifier=instance_b_id),
                 *instance_b_gone)
    expect_error(lambda: neptune.describe_db_clusters(DBClusterIdentifier=cluster_id),
                 *cluster_gone)


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
