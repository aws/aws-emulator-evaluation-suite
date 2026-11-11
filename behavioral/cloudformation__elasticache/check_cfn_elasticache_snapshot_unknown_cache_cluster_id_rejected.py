"""cfn-elasticache-snapshot-unknown-cache-cluster-id-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cfn-elasticache-snapshot-unknown-cache-cluster-id-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def _cluster_template(cluster_name: str, subnet_group_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": _cluster_resources(cluster_name, subnet_group_name),
    })


def _snapshot_template(snapshot_name: str, cluster_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Snapshot": {"Type": "AWS::ElastiCache::Snapshot", "Properties": {
            "SnapshotName": snapshot_name, "CacheClusterId": cluster_id}}},
        "Outputs": {"SnapshotArn": {"Value": {"Ref": "Snapshot"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ElastiCache Snapshot naming a CacheClusterId that does not exist is refused.

    The handler relays ElastiCache's exact not-found reason and no snapshot of that name exists,
    while the same template naming a real cluster deploys a snapshot ElastiCache reads back.
    """
    cfn = ctx.client("cloudformation")
    ec = ctx.client("elasticache")

    bogus_cluster_id = ctx.unique_name("sim2real-behav-ecnx-")
    bad_snapshot = ctx.unique_name("sim2real-behav-ecsnap-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-ecsnapbad-"),
                          _snapshot_template(bad_snapshot, bogus_cluster_id))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Snapshot"), ctx.account,
                         bad_snapshot)
    want = (f"Cache cluster not found: {bogus_cluster_id} (Service: ElastiCache; Operation: "
            "CreateSnapshot; Status Code: 404; Error Code: CacheClusterNotFoundFault; "
            "Request ID: <id>)", "NotFound")
    assert got == want, f"handler reason {got!r}, expected {want!r}"
    # Absence through ElastiCache, by the name the snapshot would have, before this check deletes.
    left = paginate(ec, "describe_snapshots", "Snapshots", SnapshotName=bad_snapshot)
    assert left == [], f"DescribeSnapshots({bad_snapshot!r}) returned {left!r}"
    delete_stack(cfn, bad_id)

    # Positive control: the same Snapshot template naming a real cluster.
    cluster_name = ctx.unique_name("sim2real-behav-eccl-")
    cluster_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-ecclstack-"),
                              _cluster_template(cluster_name, ctx.unique_name("sim2real-behav-ecsng-")))
    status = wait_stack(cfn, cluster_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", f"cluster stack ended {status!r}"
    good_snapshot = ctx.unique_name("sim2real-behav-ecsnapok-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-ecsnapok-"),
                           _snapshot_template(good_snapshot, cluster_name))
    status = wait_stack(cfn, good_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    arn = stack_outputs(cfn, good_id)["SnapshotArn"]
    snaps = [(s["ARN"], s["CacheClusterId"], s["SnapshotStatus"])
             for s in paginate(ec, "describe_snapshots", "Snapshots", SnapshotName=good_snapshot)]
    assert snaps == [(arn, cluster_name, "available")], f"control snapshot reads {snaps!r}"
    delete_stack(cfn, good_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
