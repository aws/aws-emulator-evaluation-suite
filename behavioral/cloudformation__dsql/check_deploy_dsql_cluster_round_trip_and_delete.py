"""deploy-dsql-cluster-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dsql-cluster-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "dsql"]

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


def _template(tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cluster": {
                "Type": "AWS::DSQL::Cluster",
                "Properties": {
                    "DeletionProtectionEnabled": False,
                    "Tags": [{"Key": "sim2real-check", "Value": tag_value}],
                },
            },
        },
        "Outputs": {
            "ClusterId": {"Value": {"Ref": "Cluster"}},
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "ResourceArn"]}},
            "ClusterStatus": {"Value": {"Fn::GetAtt": ["Cluster", "Status"]}},
            "ClusterCreationTime": {"Value": {"Fn::GetAtt": ["Cluster", "CreationTime"]}},
            "ClusterEndpoint": {"Value": {"Fn::GetAtt": ["Cluster", "Endpoint"]}},
        },
    })


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DSQL::Cluster reaches DSQL's own ACTIVE status with the declared
    DeletionProtectionEnabled, tags, arn, endpoint and creation time; deleting the stack removes the
    cluster from DSQL.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dsql-cluster.html
    """
    cfn = ctx.client("cloudformation")
    dsql = ctx.client("dsql")
    stack = ctx.unique_name("sim2real-dsqlcluster-")

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK))
    status = wait_stack(cfn, stack_id, timeout_s=400.0)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    cluster_id = outputs["ClusterId"]
    arn_output = outputs["ClusterArn"]
    status_output = outputs["ClusterStatus"]
    endpoint_output = outputs["ClusterEndpoint"]
    creation_output = outputs["ClusterCreationTime"]

    # ListClusters, read on every page, holds the stack's cluster under its Ref and ARN output.
    listed = [(c["identifier"], c["arn"]) for c in paginate(dsql, "list_clusters", "clusters")
              if c["arn"] == arn_output]
    assert listed == [(cluster_id, arn_output)], (
        f"ListClusters entries for {arn_output!r}: {listed!r}, expected Ref {cluster_id!r}"
    )
    cluster = dsql.get_cluster(identifier=cluster_id)
    assert cluster["identifier"] == cluster_id, (
        f"expected GetCluster identifier to equal the stack's Ref {cluster_id!r}, "
        f"DSQL reports {cluster['identifier']!r}"
    )
    assert cluster["arn"] == arn_output, (
        f"expected GetCluster arn to equal the ResourceArn output {arn_output!r}, "
        f"DSQL reports {cluster['arn']!r}"
    )
    assert cluster["status"] == status_output, (
        f"expected GetCluster status to equal the Status output {status_output!r}, "
        f"DSQL reports {cluster['status']!r}"
    )
    assert cluster["status"] == "ACTIVE", (
        f"expected the cluster to settle in ACTIVE once CREATE_COMPLETE, DSQL reports "
        f"{cluster['status']!r}"
    )
    assert cluster["deletionProtectionEnabled"] is False, (
        f"expected the template's DeletionProtectionEnabled false to read back as False, "
        f"DSQL reports {cluster['deletionProtectionEnabled']!r}"
    )
    assert cluster["endpoint"] == endpoint_output, (
        f"expected GetCluster endpoint to equal the Endpoint output {endpoint_output!r}, "
        f"DSQL reports {cluster['endpoint']!r}"
    )
    assert cluster["creationTime"] == _parse_iso8601(creation_output), (
        f"expected GetCluster creationTime to equal the CreationTime output {creation_output!r}, "
        f"DSQL reports {cluster['creationTime']!r}"
    )
    tag_list = dsql.list_tags_for_resource(resourceArn=arn_output)["tags"]
    # The template's tag plus the aws:cloudformation:* tags CloudFormation adds to the cluster;
    # the stack's own sim2real tag is not asserted here.
    got_tags = {k: v for k, v in tag_list.items() if k != "sim2real"}
    want_tags = {"sim2real-check": CHECK, "aws:cloudformation:stack-name": stack,
                 "aws:cloudformation:logical-id": "Cluster",
                 "aws:cloudformation:stack-id": stack_id}
    assert got_tags == want_tags, (
        f"expected the template's Tags to read back as {want_tags!r}, DSQL reports {got_tags!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    cluster_gone = (
        "ResourceNotFoundException",
        f"The resource with ARN {arn_output} doesn't exist. Verify the ARN and try again.",
    )
    expect_error(lambda: dsql.get_cluster(identifier=cluster_id), *cluster_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
