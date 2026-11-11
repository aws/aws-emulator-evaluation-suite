"""deploy-cfn-msk-serverless-cluster-provisions-and-tears-down."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-msk-serverless-cluster-provisions-and-tears-down"
GROUP = "deploy"
SERVICES = ["cloudformation", "kafka"]

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

_GONE = ("NotFoundException", "The requested resource doesn\u2019t exist.")

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ClusterName: {Type: String}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.91.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.91.0.0/24
      AvailabilityZone: !Select [0, !GetAZs ""]
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.91.1.0/24
      AvailabilityZone: !Select [1, !GetAZs ""]
  ClusterSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real msk serverless provisioning sg
      VpcId: !Ref Vpc
  ServerlessCluster:
    Type: AWS::MSK::ServerlessCluster
    Properties:
      ClusterName: !Ref ClusterName
      ClientAuthentication:
        Sasl:
          Iam:
            Enabled: true
      VpcConfigs:
        - SubnetIds: [!Ref SubnetA, !Ref SubnetB]
          SecurityGroups: [!Ref ClusterSG]
Outputs:
  ClusterArnRef:
    Value: !Ref ServerlessCluster
  ClusterArnGetAtt:
    Value: !GetAtt ServerlessCluster.Arn
  SubnetAId:
    Value: !Ref SubnetA
  SubnetBId:
    Value: !Ref SubnetB
  ClusterSGId:
    Value: !Ref ClusterSG
"""


def _clusters(kafka, name: str) -> list[dict]:
    """The clusters named exactly ``name`` (the filter is a prefix), every page."""
    return [c for c in paginate(kafka, "list_clusters_v2", "ClusterInfoList",
                                ClusterNameFilter=name) if c["ClusterName"] == name]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::MSK::ServerlessCluster is a real MSK cluster, removed with its stack.

    Ref and the Arn GetAtt match the cluster ListClustersV2 lists under its exact name, every set
    property reads back through DescribeClusterV2, and after the delete MSK answers NotFound.
    """
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")
    cluster_name = ctx.unique_name("sim2real-mskcfn-")

    stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-mskcfn-stack-"), _TEMPLATE,
        Parameters=[{"ParameterKey": "ClusterName", "ParameterValue": cluster_name}],
    )
    status = wait_stack(cfn, stack_id, timeout_s=1200.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    found = [c["ClusterArn"] for c in _clusters(kafka, cluster_name)]
    assert found == [outputs["ClusterArnRef"]] == [outputs["ClusterArnGetAtt"]], (
        f"ListClustersV2 lists {found!r} for {cluster_name!r}; outputs {outputs!r}"
    )
    info = kafka.describe_cluster_v2(ClusterArn=found[0])["ClusterInfo"]
    serverless = info["Serverless"]
    got = {
        "ClusterName": info["ClusterName"],
        "State": info["State"],
        "ClusterType": info["ClusterType"],
        "Iam": serverless["ClientAuthentication"]["Sasl"]["Iam"]["Enabled"],
        "VpcConfigs": [(sorted(v["SubnetIds"]), v["SecurityGroupIds"])
                       for v in serverless["VpcConfigs"]],
    }
    want = {
        "ClusterName": cluster_name, "State": "ACTIVE", "ClusterType": "SERVERLESS", "Iam": True,
        "VpcConfigs": [(sorted([outputs["SubnetAId"], outputs["SubnetBId"]]),
                        [outputs["ClusterSGId"]])],
    }
    assert got == want, f"DescribeClusterV2 reads {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    remaining = _clusters(kafka, cluster_name)
    assert remaining == [], f"ListClustersV2 still lists {remaining!r} after the delete"
    expect_error(lambda: kafka.describe_cluster_v2(ClusterArn=found[0]), *_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
