"""deploy-appflow-flow-missing-bucket-policy-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appflow-flow-missing-bucket-policy-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["appflow", "cloudformation", "s3"]

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

_SRC_PREFIX = "input"
_DST_PREFIX = "output"
_APPFLOW_PRINCIPAL = "appflow.amazonaws.com"


def _template(flow_name: str, src_bucket: str, dst_bucket: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Flow": {"Type": "AWS::AppFlow::Flow", "Properties": {
                "FlowName": flow_name,
                "TriggerConfig": {"TriggerType": "OnDemand"},
                "SourceFlowConfig": {
                    "ConnectorType": "S3",
                    "SourceConnectorProperties": {"S3": {
                        "BucketName": src_bucket, "BucketPrefix": _SRC_PREFIX}},
                },
                "DestinationFlowConfigList": [{
                    "ConnectorType": "S3",
                    "DestinationConnectorProperties": {"S3": {
                        "BucketName": dst_bucket, "BucketPrefix": _DST_PREFIX,
                        "S3OutputFormatConfig": {"FileType": "JSON"}}},
                }],
                "Tasks": [{
                    "SourceFields": [],
                    "TaskType": "Map_all",
                    "TaskProperties": [{"Key": "EXCLUDE_SOURCE_FIELDS_LIST", "Value": "[]"}],
                }],
            }},
        },
    })


def _make_bucket(ctx, kind: str) -> str:
    """A tagged bucket; its delete is registered before the create."""
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-cfafneg-{kind}-").lower().replace("_", "-")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": name}]})
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    """Empty and delete the bucket; only its own NoSuchBucket means it was never created."""
    try:
        for obj in paginate(s3, "list_objects_v2", "Contents", Bucket=name):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _appflow_policy(ctx, s3, sid: str, actions: list, bucket: str) -> str:
    """A bucket policy granting AppFlow ``actions``, only for flows in this account."""
    arn = f"arn:{s3.meta.partition}:s3:::{bucket}"
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": sid,
            "Effect": "Allow",
            "Principal": {"Service": _APPFLOW_PRINCIPAL},
            "Action": actions,
            "Resource": [arn, f"{arn}/*"],
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
        }],
    })


def _grant_source(ctx, s3, bucket: str) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=_appflow_policy(
        ctx, s3, "AllowAppFlowSourceActions", ["s3:ListBucket", "s3:GetObject"], bucket))


def _grant_destination(ctx, s3, bucket: str) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=_appflow_policy(
        ctx, s3, "AllowAppFlowDestinationActions", [
            "s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
            "s3:ListBucketMultipartUploads", "s3:GetBucketAcl", "s3:PutObjectAcl",
        ], bucket))


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack whose AppFlow S3 source bucket carries no AppFlow bucket policy fails the
    Flow resource with AppFlow's own validation message, rolls the stack back, and never
    creates the flow -- confirmed through AppFlow's own API, not just the stack status.
    """
    cf = ctx.client("cloudformation")
    appflow = ctx.client("appflow")
    s3 = ctx.client("s3")

    src_bucket = _make_bucket(ctx, "src")
    dst_bucket = _make_bucket(ctx, "dst")
    _grant_destination(ctx, s3, dst_bucket)
    # src_bucket intentionally carries NO bucket policy granting appflow.amazonaws.com access.
    s3.put_object(Bucket=src_bucket, Key=f"{_SRC_PREFIX}/data.csv", Body=b"id,message\n1,x\n")

    flow_name = ctx.unique_name("sim2real-cfafneg-flow-")
    stack = ctx.unique_name("sim2real-cfafneg-stack-")

    bad_id = create_stack(ctx, cf, stack, _template(flow_name, src_bucket, dst_bucket))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, stack ended in {status!r}"

    events = stack_events(cf, bad_id)
    want_rows = [("Flow", "CREATE_FAILED"), (stack, "ROLLBACK_COMPLETE")]
    decisive = [row for row in decisive_rows(events) if row in want_rows]
    assert decisive == want_rows, f"unexpected decisive event order: {decisive!r}"

    partition = bad_id.split(":")[1]
    want = (
        "Invalid request provided: AWS::AppFlow::FlowCreate "
        f"Flow request failed: [The provided S3 Bucket [{src_bucket}] is missing the following "
        "permitted actions: [s3:listbucket, s3:getobject]\n. These policies must be applied to the "
        f"[{_APPFLOW_PRINCIPAL}] service principal and must be attached to all the following "
        f"resources: [arn:{partition}:s3:::{src_bucket}, arn:{partition}:s3:::{src_bucket}/*]] "
        "(Service: Appflow, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "InvalidRequest",
    )
    got = handler_reason(failed_reason(events, "Flow"), ctx.account)
    assert got == want, f"unexpected (masked message, handler code) {got!r}, wanted {want!r}"

    # The failure is absent-of-effect, via an independent read: no flow was ever created.
    flow_absent = ("ResourceNotFoundException", f"There is no flow with the name {flow_name}")
    expect_error(lambda: appflow.describe_flow(flowName=flow_name), *flow_absent)

    # Positive control, in the same file: granting the identical missing policy and
    # retrying lets the same stack deploy, proving the earlier rejection was the policy alone.
    _grant_source(ctx, s3, src_bucket)
    delete_stack(cf, bad_id)
    good_id = create_stack(ctx, cf, stack, _template(flow_name, src_bucket, dst_bucket))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"expected the restored stack to reach CREATE_COMPLETE, got {status!r}"
    restored = appflow.describe_flow(flowName=flow_name)
    assert restored["flowStatus"] == "Active", restored["flowStatus"]
    assert restored["triggerConfig"]["triggerType"] == "OnDemand", restored["triggerConfig"]
    src_cfg = restored["sourceFlowConfig"]["sourceConnectorProperties"]["S3"]
    assert (src_cfg["bucketName"], src_cfg["bucketPrefix"]) == (src_bucket, _SRC_PREFIX), (
        f"the control flow's source is {src_cfg!r}, expected {src_bucket!r} under {_SRC_PREFIX!r}")
    dst_cfg = restored["destinationFlowConfigList"][0]["destinationConnectorProperties"]["S3"]
    assert (dst_cfg["bucketName"], dst_cfg["bucketPrefix"]) == (dst_bucket, _DST_PREFIX), (
        f"the control flow's destination is {dst_cfg!r}, expected {dst_bucket!r} under {_DST_PREFIX!r}")
    assert dst_cfg["s3OutputFormatConfig"]["fileType"] == "JSON", dst_cfg["s3OutputFormatConfig"]
    # The templated Map_all task, which AppFlow expands against the source CSV's id and message
    # columns into one Map per column and a trailing Filter.
    task_types = [t["taskType"] for t in restored["tasks"]]
    assert task_types == ["Map_all", "Map", "Map", "Filter"], (
        f"DescribeFlow tasks are {task_types!r}, expected the Map_all expansion for id+message")
    map_all = [t.get("taskProperties") for t in restored["tasks"] if t["taskType"] == "Map_all"]
    assert map_all == [{"EXCLUDE_SOURCE_FIELDS_LIST": "[]"}], (
        f"the Map_all task's taskProperties are {map_all!r}, expected the template's "
        "EXCLUDE_SOURCE_FIELDS_LIST of []")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
