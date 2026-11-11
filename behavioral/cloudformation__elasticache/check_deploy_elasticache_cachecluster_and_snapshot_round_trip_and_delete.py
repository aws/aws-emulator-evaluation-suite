"""deploy-elasticache-cachecluster-and-snapshot-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elasticache-cachecluster-and-snapshot-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticache"]

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


_VPC_CIDR = "10.212.0.0/16"
_SUBNET_CIDRS = ["10.212.1.0/24", "10.212.2.0/24"]
_SUBNET_GROUP_DESCRIPTION = "sim2real throwaway subnet group"
_NODE_TYPE = "cache.t4g.micro"
_CREATE_TIMEOUT_S = 1500.0


def _cluster_resources(cluster_name: str, subnet_group_name: str) -> dict:
    """A private VPC, two subnets, an SG, a subnet group and a one-node Redis cluster."""
    az = [{"Fn::Select": [i, {"Fn::GetAZs": ""}]} for i in range(2)]
    return {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDRS[0], "AvailabilityZone": az[0]}},
        "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDRS[1], "AvailabilityZone": az[1]}},
        "SecurityGroup": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "GroupDescription": "sim2real throwaway cache security group"}},
        "SubnetGroup": {"Type": "AWS::ElastiCache::SubnetGroup", "Properties": {
            "CacheSubnetGroupName": subnet_group_name, "Description": _SUBNET_GROUP_DESCRIPTION,
            "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]}},
        "Cluster": {"Type": "AWS::ElastiCache::CacheCluster", "Properties": {
            "ClusterName": cluster_name, "Engine": "redis", "CacheNodeType": _NODE_TYPE,
            "NumCacheNodes": 1, "CacheSubnetGroupName": {"Ref": "SubnetGroup"},
            "VpcSecurityGroupIds": [{"Ref": "SecurityGroup"}]}},
    }


def _template(cluster_name: str, subnet_group_name: str, snapshot_name: str,
              with_snapshot: bool = True) -> str:
    resources = _cluster_resources(cluster_name, subnet_group_name)
    outputs = {
        "SubnetA": {"Value": {"Ref": "SubnetA"}},
        "SubnetB": {"Value": {"Ref": "SubnetB"}},
        "SecurityGroupId": {"Value": {"Ref": "SecurityGroup"}},
        "SubnetGroupName": {"Value": {"Ref": "SubnetGroup"}},
        "ClusterId": {"Value": {"Ref": "Cluster"}},
    }
    if with_snapshot:
        resources["Snapshot"] = {"Type": "AWS::ElastiCache::Snapshot", "Properties": {
            "SnapshotName": snapshot_name, "CacheClusterId": {"Ref": "Cluster"}}}
        outputs["SnapshotArn"] = {"Value": {"Ref": "Snapshot"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _available_snapshot(ec, name: str) -> dict:
    """DescribeSnapshots polled (bounded) until the named snapshot is 'available'."""
    deadline = time.monotonic() + 600
    while True:
        snaps = paginate(ec, "describe_snapshots", "Snapshots", SnapshotName=name)
        assert len(snaps) == 1, f"DescribeSnapshots({name!r}) returned {snaps!r}"
        if snaps[0]["SnapshotStatus"] == "available":
            return snaps[0]
        assert time.monotonic() < deadline, f"snapshot {name!r} still {snaps[0]['SnapshotStatus']!r}"
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ElastiCache Snapshot of a stack's cache cluster reads back through ElastiCache.

    Its Ref, source cluster and engine match, as do the cluster's and subnet group's properties;
    an update dropping the Snapshot removes it from the still-available cluster.
    """
    ec = ctx.client("elasticache")
    cfn = ctx.client("cloudformation")
    cluster_name = ctx.unique_name("sim2real-eccsn-")
    subnet_group_name = ctx.unique_name("sim2real-eccsn-")
    snapshot_name = ctx.unique_name("sim2real-eccsn-")
    names = (cluster_name, subnet_group_name, snapshot_name)

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-eccsn-"), _template(*names))
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assert (out["ClusterId"], out["SubnetGroupName"]) == (cluster_name, subnet_group_name), out

    # The supporting cluster and subnet group carry every templated property.
    cluster = ec.describe_cache_clusters(CacheClusterId=cluster_name)["CacheClusters"][0]
    got = (cluster["CacheClusterStatus"], cluster["Engine"], cluster["CacheNodeType"],
           cluster["NumCacheNodes"], cluster["CacheSubnetGroupName"],
           [g["SecurityGroupId"] for g in cluster["SecurityGroups"]])
    want = ("available", "redis", _NODE_TYPE, 1, subnet_group_name, [out["SecurityGroupId"]])
    assert got == want, f"cache cluster reads {got!r}, expected {want!r}"
    group = ec.describe_cache_subnet_groups(
        CacheSubnetGroupName=subnet_group_name)["CacheSubnetGroups"][0]
    got = (group["CacheSubnetGroupDescription"],
           sorted(s["SubnetIdentifier"] for s in group["Subnets"]))
    assert got == (_SUBNET_GROUP_DESCRIPTION, sorted([out["SubnetA"], out["SubnetB"]])), (
        f"subnet group reads {got!r}"
    )

    # The snapshot: Ref (its ARN), source cluster and engine, from the listing by name.
    snap = _available_snapshot(ec, snapshot_name)
    got = (snap["ARN"], snap["CacheClusterId"], snap["Engine"], snap["SnapshotSource"])
    assert got == (out["SnapshotArn"], cluster_name, "redis", "manual"), f"snapshot reads {got!r}"

    # The snapshot's own delete: an update dropping it while the cluster stays available.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(*names, with_snapshot=False))
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "UPDATE_COMPLETE", f"snapshot-removing update ended {status!r}"
    # The snapshot's delete is asynchronous: it can still list (deleting) after UPDATE_COMPLETE.
    deadline = time.monotonic() + 300
    while left := paginate(ec, "describe_snapshots", "Snapshots", SnapshotName=snapshot_name):
        assert time.monotonic() < deadline, (
            f"after dropping the Snapshot it still lists as "
            f"{[x['SnapshotStatus'] for x in left]!r} after 300s: {left!r}"
        )
        time.sleep(5)
    state = ec.describe_cache_clusters(CacheClusterId=cluster_name)["CacheClusters"][0]
    assert state["CacheClusterStatus"] == "available", f"cluster after the update {state!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: ec.describe_cache_clusters(CacheClusterId=cluster_name),
                 *("CacheClusterNotFound", f"CacheCluster not found: {cluster_name}"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
