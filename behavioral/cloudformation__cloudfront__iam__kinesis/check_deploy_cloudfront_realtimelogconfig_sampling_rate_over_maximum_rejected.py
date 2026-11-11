"""deploy-cloudfront-realtimelogconfig-sampling-rate-over-maximum-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cloudfront-realtimelogconfig-sampling-rate-over-maximum-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront", "iam", "kinesis"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_POLICY_NAME = "sim2real-cfnrlc-kinesis-put"
_FIELDS = ["timestamp", "c-ip"]
_TRUST_CLOUDFRONT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_REJECTED = (
    "Model validation failed (#/SamplingRate: failed validation constraint for keyword "
    "[maximum])",
    "InvalidRequest",
)


def _put_policy(stream_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                       "Resource": stream_arn}],
    }


def _template(stream_name, role_name, rlc_name, sampling_rate):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Stream": {"Type": "AWS::Kinesis::Stream",
                       "Properties": {"ShardCount": 1, "Name": stream_name}},
            "Role": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST_CLOUDFRONT,
                "Policies": [{"PolicyName": _POLICY_NAME,
                              "PolicyDocument": _put_policy({"Fn::GetAtt": ["Stream", "Arn"]})}],
            }},
            "RLC": {"Type": "AWS::CloudFront::RealtimeLogConfig", "Properties": {
                "Name": rlc_name,
                "EndPoints": [{"StreamType": "Kinesis", "KinesisStreamConfig": {
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "StreamArn": {"Fn::GetAtt": ["Stream", "Arn"]},
                }}],
                "Fields": _FIELDS,
                "SamplingRate": sampling_rate,
            }},
        },
    })


def _listed_configs(cfront):
    """Every ListRealtimeLogConfigs item; the op has no botocore paginator, so follow NextMarker."""
    listed, marker = [], ""
    while True:
        page = (cfront.list_realtime_log_configs(Marker=marker) if marker
                else cfront.list_realtime_log_configs())["RealtimeLogConfigs"]
        listed.extend(page.get("Items", []))
        marker = page.get("NextMarker")
        if not marker:
            return listed


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation RealtimeLogConfig with SamplingRate above the maximum of 100 fails and
    rolls back with no config left, while the same template at 100 deploys and reads back.
    """
    cfront = ctx.client("cloudfront")
    cf = ctx.client("cloudformation")
    iam = ctx.client("iam")
    kinesis = ctx.client("kinesis")
    good_stream = ctx.unique_name("sim2real-cfnrlc-good-stream-")
    good_role = ctx.unique_name("sim2real-cfnrlc-good-role-")
    good_name = ctx.unique_name("sim2real-cfnrlc-good-")
    bad_name = ctx.unique_name("sim2real-cfnrlc-bad-")

    # Positive control: same template, the one property given a VALID value (never dropped).
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnrlc-goodstack-"),
                           _template(good_stream, good_role, good_name, 100),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    partition = good_id.split(":")[1]
    stream_arn = f"arn:{partition}:kinesis:{ctx.region}:{ctx.account}:stream/{good_stream}"
    role_arn = f"arn:{partition}:iam::{ctx.account}:role/{good_role}"
    stream = kinesis.describe_stream_summary(StreamName=good_stream)["StreamDescriptionSummary"]
    got = (stream["StreamARN"], stream["OpenShardCount"])
    assert got == (stream_arn, 1), f"control stream reads {got!r}"
    doc = iam.get_role_policy(RoleName=good_role, PolicyName=_POLICY_NAME)["PolicyDocument"]
    assert doc == _put_policy(stream_arn), f"control role policy {doc!r}"
    rlc = cfront.get_realtime_log_config(Name=good_name)["RealtimeLogConfig"]
    want = {
        "ARN": f"arn:{partition}:cloudfront::{ctx.account}:realtime-log-config/{good_name}",
        "Name": good_name, "SamplingRate": 100, "Fields": _FIELDS,
        "EndPoints": [{"StreamType": "Kinesis", "KinesisStreamConfig": {
            "RoleARN": role_arn, "StreamARN": stream_arn}}],
    }
    assert rlc == want, f"control config reads {rlc!r}, expected {want!r}"

    # The rejected template differs only in SamplingRate (and the per-run names).
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnrlc-badstack-"),
                          _template(ctx.unique_name("sim2real-cfnrlc-bad-stream-"),
                                    ctx.unique_name("sim2real-cfnrlc-bad-role-"), bad_name, 101),
                          Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    got = handler_reason(failed_reason(stack_events(cf, bad_id), "RLC"), ctx.account, bad_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through CloudFront, BEFORE this check's own delete, while the control's
    # config is listed by the same read.
    names = [c["Name"] for c in _listed_configs(cfront)]
    assert (good_name in names, bad_name in names) == (True, False), (
        f"ListRealtimeLogConfigs names: control {good_name in names}, rejected {bad_name in names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
