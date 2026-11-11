"""deploy-cfn-msk-serverless-cluster-rejects-iam-auth-disabled."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-msk-serverless-cluster-rejects-iam-auth-disabled"
GROUP = "deploy"
SERVICES = ["cloudformation", "kafka"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "[ClientRequestToken: <token>] A serverless cluster must use SASL/IAM authentication. "
    "(Service: Kafka, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>) "
    "'clientAuthentication'",
    "InvalidRequest",
)


def _template(iam_enabled: bool) -> str:
    return f"""
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ClusterName: {{Type: String}}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.92.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.92.0.0/24
      AvailabilityZone: !Select [0, !GetAZs ""]
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.92.1.0/24
      AvailabilityZone: !Select [1, !GetAZs ""]
  ServerlessCluster:
    Type: AWS::MSK::ServerlessCluster
    Properties:
      ClusterName: !Ref ClusterName
      ClientAuthentication:
        Sasl:
          Iam:
            Enabled: {str(iam_enabled).lower()}
      VpcConfigs:
        - SubnetIds: [!Ref SubnetA, !Ref SubnetB]
Outputs:
  SubnetAId:
    Value: !Ref SubnetA
  SubnetBId:
    Value: !Ref SubnetB
"""


def _clusters(kafka, name: str) -> list[dict]:
    """The clusters named exactly ``name`` (the filter is a prefix), every page."""
    return [c for c in paginate(kafka, "list_clusters_v2", "ClusterInfoList",
                                ClusterNameFilter=name) if c["ClusterName"] == name]


def _reasons(events):
    """``(logical id, status, reason)`` of every event row with a reason, oldest first."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e["ResourceStatusReason"])
            for e in events if e.get("ResourceStatusReason")]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::MSK::ServerlessCluster with SASL/IAM authentication disabled is refused by MSK.

    The stack rolls back with MSK's reason naming clientAuthentication and no cluster is listed,
    while the same template with IAM enabled deploys a cluster MSK reads back with IAM on.
    """
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")
    good_name = ctx.unique_name("sim2real-mskcfn-good-")
    bad_name = ctx.unique_name("sim2real-mskcfn-neg-")

    # Both stacks start together; the control's slower create is waited on last.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mskcfn-good-stack-"),
                           _template(True),
                           Parameters=[{"ParameterKey": "ClusterName", "ParameterValue": good_name}])
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mskcfn-neg-stack-"),
                          _template(False),
                          Parameters=[{"ParameterKey": "ClusterName", "ParameterValue": bad_name}])
    status = wait_stack(cfn, bad_id, timeout_s=900.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "ServerlessCluster")
    got = handler_reason(reason, ctx.account, bad_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through MSK, by the exact name the cluster would have had.
    found = _clusters(kafka, bad_name)
    assert found == [], f"ListClustersV2 lists the rejected cluster: {found!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id, timeout_s=1200.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {_reasons(stack_events(cfn, good_id))!r}"
    )
    outputs = stack_outputs(cfn, good_id)
    found = _clusters(kafka, good_name)
    assert len(found) == 1, f"ListClustersV2 lists {found!r} for the control"
    serverless = kafka.describe_cluster_v2(
        ClusterArn=found[0]["ClusterArn"])["ClusterInfo"]["Serverless"]
    got = (serverless["ClientAuthentication"]["Sasl"]["Iam"]["Enabled"],
           [sorted(v["SubnetIds"]) for v in serverless["VpcConfigs"]])
    want = (True, [sorted([outputs["SubnetAId"], outputs["SubnetBId"]])])
    assert got == want, f"the control cluster reads {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
