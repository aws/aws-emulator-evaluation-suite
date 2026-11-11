"""deploy-neptune-cluster-and-instance-provisioned."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-neptune-cluster-and-instance-provisioned"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "neptune"]

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


#: A private VPC, a two-AZ subnet group, a Neptune cluster and one instance in it.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: A Neptune cluster and one instance in a dedicated VPC.
Parameters:
  AzA: {Type: String}
  AzB: {Type: String}
  ClusterId: {Type: String}
  InstanceId: {Type: String}
  SubnetGroupName: {Type: String}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.61.0.0/16
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.61.1.0/24
      AvailabilityZone: !Ref AzA
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.61.2.0/24
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
  Instance:
    Type: AWS::Neptune::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceIdentifier: !Ref InstanceId
      DBInstanceClass: db.t3.medium
      DBClusterIdentifier: !Ref Cluster
Outputs:
  ClusterRef: {Value: !Ref Cluster}
  ClusterEndpoint: {Value: !GetAtt Cluster.Endpoint}
  ClusterReadEndpoint: {Value: !GetAtt Cluster.ReadEndpoint}
  ClusterPort: {Value: !GetAtt Cluster.Port}
  ClusterResourceId: {Value: !GetAtt Cluster.ClusterResourceId}
  SecurityGroupId: {Value: !Ref ClusterSg}
  SubnetAId: {Value: !Ref SubnetA}
  SubnetBId: {Value: !Ref SubnetB}
  InstanceRef: {Value: !Ref Instance}
  InstanceEndpoint: {Value: !GetAtt Instance.Endpoint}
  InstancePort: {Value: !GetAtt Instance.Port}
"""

#: A cluster is a few minutes; an instance inside it several more.
_CREATE_TIMEOUT_S = 1500.0
#: The stack delete has outlasted the helper's 600 s, so the create and the in-check delete share
#: one deadline under the Neptune suite budget (2700 s).
_RUN_BUDGET_S = 2640.0


def _delete_slow_stack(cf, stack_id, timeout_s):
    """Delete by StackId and wait up to ``timeout_s``; raise unless DELETE_COMPLETE."""
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s)
    if status != "DELETE_COMPLETE":
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in stack_events(cf, stack_id) if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack really provisions a Neptune cluster and instance, not just a claim.

    Ref, every GetAtt and the subnet group read back through Neptune; the stack delete removes
    the instance, the cluster and the subnet group, each proven by Neptune's exact NotFound.
    """
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    neptune = ctx.client("neptune")
    cfn = ctx.client("cloudformation")

    az_a, az_b = _two_usable_azs(ec2, neptune)
    cluster_id = ctx.unique_name("sim2real-ncl-")
    instance_id = ctx.unique_name("sim2real-nin-")
    subnet_group = ctx.unique_name("sim2real-nsg-")
    stack_name = ctx.unique_name("sim2real-neptune-stack-")

    deadline = time.monotonic() + _RUN_BUDGET_S
    stack_id = create_stack(
        ctx, cfn, stack_name, _TEMPLATE,
        Parameters=[
            {"ParameterKey": "AzA", "ParameterValue": az_a},
            {"ParameterKey": "AzB", "ParameterValue": az_b},
            {"ParameterKey": "ClusterId", "ParameterValue": cluster_id},
            {"ParameterKey": "InstanceId", "ParameterValue": instance_id},
            {"ParameterKey": "SubnetGroupName", "ParameterValue": subnet_group},
        ],
    )
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    assert outputs["ClusterRef"] == cluster_id, (
        f"Ref of the cluster is {outputs['ClusterRef']!r}, expected the identifier {cluster_id!r}"
    )
    assert outputs["InstanceRef"] == instance_id, (
        f"Ref of the instance is {outputs['InstanceRef']!r}, expected the identifier {instance_id!r}"
    )

    # Refs against independent reads: the cluster's own member list names the instance.
    clusters = [c for c in paginate(neptune, "describe_db_clusters", "DBClusters",
                                    Filters=[{"Name": "engine", "Values": ["neptune"]}])
                if c["DBClusterIdentifier"] == cluster_id]
    assert len(clusters) == 1, f"DescribeDBClusters lists {clusters!r} for {cluster_id!r}"
    cluster = clusters[0]
    members = [m["DBInstanceIdentifier"] for m in cluster["DBClusterMembers"]]
    assert members == [instance_id], f"cluster members {members!r}, expected [{instance_id!r}]"
    assert cluster["Status"] == "available", f"cluster {cluster_id!r} is {cluster['Status']!r}"
    seen_cluster = {
        "Endpoint": cluster["Endpoint"],
        "ReaderEndpoint": cluster["ReaderEndpoint"],
        "Port": str(cluster["Port"]),
        "DbClusterResourceId": cluster["DbClusterResourceId"],
        "DeletionProtection": cluster["DeletionProtection"],
        "VpcSecurityGroupIds": sorted(g["VpcSecurityGroupId"] for g in cluster["VpcSecurityGroups"]),
        "DBSubnetGroup": cluster["DBSubnetGroup"],
    }
    want_cluster = {
        "Endpoint": outputs["ClusterEndpoint"],
        "ReaderEndpoint": outputs["ClusterReadEndpoint"],
        "Port": outputs["ClusterPort"],
        "DbClusterResourceId": outputs["ClusterResourceId"],
        "DeletionProtection": False,
        "VpcSecurityGroupIds": [outputs["SecurityGroupId"]],
        "DBSubnetGroup": subnet_group,
    }
    assert seen_cluster == want_cluster, (
        f"neptune.describe_db_clusters({cluster_id!r}) reads {seen_cluster!r}, expected the "
        f"template's GetAtt outputs and properties {want_cluster!r}"
    )

    instances = neptune.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"]
    assert len(instances) == 1, f"DescribeDBInstances({instance_id!r}) returned {instances!r}"
    instance = instances[0]
    assert instance["DBInstanceStatus"] == "available", (
        f"instance {instance_id!r} is {instance['DBInstanceStatus']!r}"
    )
    seen_instance = {
        "Address": instance["Endpoint"]["Address"],
        "Port": str(instance["Endpoint"]["Port"]),
        "DBInstanceClass": instance["DBInstanceClass"],
        "DBClusterIdentifier": instance["DBClusterIdentifier"],
    }
    want_instance = {
        "Address": outputs["InstanceEndpoint"],
        "Port": outputs["InstancePort"],
        "DBInstanceClass": "db.t3.medium",
        "DBClusterIdentifier": cluster_id,
    }
    assert seen_instance == want_instance, (
        f"neptune.describe_db_instances({instance_id!r}) reads {seen_instance!r}, expected the "
        f"template's GetAtt outputs and properties {want_instance!r}"
    )

    groups = neptune.describe_db_subnet_groups(DBSubnetGroupName=subnet_group)["DBSubnetGroups"]
    got = [(g["DBSubnetGroupDescription"], sorted(x["SubnetIdentifier"] for x in g["Subnets"]))
           for g in groups]
    want = [("Subnet group for a Neptune cluster",
             sorted([outputs["SubnetAId"], outputs["SubnetBId"]]))]
    assert got == want, f"subnet group {subnet_group!r} reads {got!r}, expected {want!r}"

    # The stack delete removes the instance, then the cluster and its subnet group.
    _delete_slow_stack(cfn, stack_id, deadline - time.monotonic())
    instance_gone = ("DBInstanceNotFound", f"DBInstance {instance_id} not found.")
    cluster_gone = ("DBClusterNotFoundFault", f"DBCluster {cluster_id} not found.")
    subnet_group_gone = ("DBSubnetGroupNotFoundFault", f"DB Subnet group '{subnet_group}' not found.")
    expect_error(lambda: neptune.describe_db_instances(DBInstanceIdentifier=instance_id),
                 *instance_gone)
    expect_error(lambda: neptune.describe_db_clusters(DBClusterIdentifier=cluster_id),
                 *cluster_gone)
    expect_error(lambda: neptune.describe_db_subnet_groups(DBSubnetGroupName=subnet_group),
                 *subnet_group_gone)


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
