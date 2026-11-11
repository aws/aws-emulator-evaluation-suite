"""deploy-dsql-cluster-invalid-kms-key-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dsql-cluster-invalid-kms-key-rejected-and-rolled-back"
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

_NONEXISTENT_KEY_ID = "00000000-0000-0000-0000-000000000000"


def _bad_template(tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cluster": {
                "Type": "AWS::DSQL::Cluster",
                "Properties": {
                    "DeletionProtectionEnabled": False,
                    "KmsEncryptionKey": {"Fn::Sub": (
                        "arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/"
                        + _NONEXISTENT_KEY_ID
                    )},
                    "Tags": [{"Key": "sim2real-check", "Value": tag_value}],
                },
            },
        },
    })


def _good_template(tag_value: str) -> str:
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
        "Outputs": {"ClusterId": {"Value": {"Ref": "Cluster"}}},
    })


def _clusters_tagged(dsql, tag_value: str) -> list[str]:
    """ARNs of every listed cluster (all pages) whose sim2real-check tag is ``tag_value``."""
    arns = [c["arn"] for page in dsql.get_paginator("list_clusters").paginate()
            for c in page["clusters"]]
    return [arn for arn in arns
            if dsql.list_tags_for_resource(resourceArn=arn).get("tags", {}).get("sim2real-check")
            == tag_value]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DSQL::Cluster naming a KMS key DSQL cannot find is rejected with
    DSQL's own exact error, and the stack rolls back leaving no cluster behind; the same
    mechanism with no KmsEncryptionKey still succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dsql-cluster.html
    """
    cfn = ctx.client("cloudformation")
    dsql = ctx.client("dsql")
    bad_stack = ctx.unique_name("sim2real-dsqlclusterbad-")

    bad_tag = ctx.unique_name("sim2real-dsqlbadtag-")
    bad_id = create_stack(ctx, cfn, bad_stack, _bad_template(bad_tag))
    partition = bad_id.split(":")[1]
    status = wait_stack(cfn, bad_id, timeout_s=400.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    got_reason = handler_reason(failed_reason(stack_events(cfn, bad_id), "Cluster"), ctx.account)
    rejected = (
        f"AWS KMS key arn:{partition}:kms:{ctx.region}:<account>:key/{_NONEXISTENT_KEY_ID} not "
        "found. Verify the key ID or ARN and ensure the key exists in your AWS account and Region."
        " (Service: Dsql, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "InvalidRequest",
    )
    assert got_reason == rejected, (
        f"expected the Cluster CREATE_FAILED reason {rejected!r}, got {got_reason!r}"
    )

    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    cluster_resources = [r for r in resources if r["LogicalResourceId"] == "Cluster"]
    assert len(cluster_resources) == 1, (
        f"expected exactly one Cluster stack resource, got {cluster_resources!r}"
    )
    assert "PhysicalResourceId" not in cluster_resources[0], (
        f"expected the rolled-back Cluster to carry no PhysicalResourceId, got "
        f"{cluster_resources[0]!r}"
    )
    leftover = _clusters_tagged(dsql, bad_tag)
    assert leftover == [], (
        f"expected DSQL to hold no cluster tagged with the rejected template's tag, found {len(leftover)}"
    )

    delete_stack(cfn, bad_id)
    stack_gone = ("ValidationError", f"Stack with id {bad_stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=bad_stack), *stack_gone)

    # Positive control: the identical mechanism, given no KmsEncryptionKey, still succeeds.
    good_stack = ctx.unique_name("sim2real-dsqlclustergood-")
    good_tag = ctx.unique_name("sim2real-dsqlgoodtag-")
    good_id = create_stack(ctx, cfn, good_stack, _good_template(good_tag))
    good_status = wait_stack(cfn, good_id, timeout_s=400.0)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    good_cluster_id = stack_outputs(cfn, good_id)["ClusterId"]
    control = dsql.get_cluster(identifier=good_cluster_id)
    # Ref against an independent read: the clusters DSQL lists under the control's own tag.
    tagged = _clusters_tagged(dsql, good_tag)
    assert tagged == [control["arn"]], (
        f"the clusters tagged {good_tag!r} are {tagged!r}, Ref {good_cluster_id!r} reads "
        f"{control['arn']!r}"
    )
    assert control["identifier"] == good_cluster_id, (
        f"GetCluster identifier {control['identifier']!r} != Ref {good_cluster_id!r}"
    )
    assert control["status"] == "ACTIVE", (
        f"expected the control cluster {good_cluster_id!r} to be ACTIVE, DSQL reports "
        f"{control['status']!r}"
    )
    assert control["deletionProtectionEnabled"] is False, (
        f"expected the control cluster's DeletionProtectionEnabled False, DSQL reports "
        f"{control['deletionProtectionEnabled']!r}"
    )
    # The template tag, exactly; the stack's own sim2real tag is not asserted here.
    control_tags = dsql.list_tags_for_resource(resourceArn=control["arn"]).get("tags", {})
    got = {k: v for k, v in control_tags.items() if k != "sim2real" and not k.startswith("aws:")}
    assert got == {"sim2real-check": good_tag}, f"the control cluster's tags are {control_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
