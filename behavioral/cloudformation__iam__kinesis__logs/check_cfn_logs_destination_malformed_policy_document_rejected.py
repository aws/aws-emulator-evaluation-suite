"""cfn-logs-destination-malformed-policy-document-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cfn-logs-destination-malformed-policy-document-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

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

_REJECTED = (
    "Invalid request provided: AWS::Logs::Destination. Error occurred while parsing accessPolicy. "
    "Please check if the accessPolicy has been constructed correctly using IAM grammar. "
    "(Service: CloudWatchLogs, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "logs.${AWS::Region}.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringLike": {
            "aws:SourceArn": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:*"}},
    }],
}


def _policy(principal, dest_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": principal},
                       "Action": "logs:PutSubscriptionFilter", "Resource": dest_arn}],
    }


def _good_policy(dest_name):
    """The template's DestinationPolicy: this account may subscribe to the destination."""
    return {"Fn::Sub": json.dumps(_policy(
        "${AWS::AccountId}",
        "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:destination:" + dest_name,
    ))}


def _template(dest_name, stream_name, role_name, policy):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Stream": {
                "Type": "AWS::Kinesis::Stream",
                "Properties": {
                    "Name": stream_name,
                    "ShardCount": 1,
                    "RetentionPeriodHours": 24,
                    "Tags": [{"Key": "sim2real-stream", "Value": stream_name}],
                },
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {"Fn::Sub": json.dumps(_TRUST)},
                    "Policies": [{
                        "PolicyName": "sim2real-put-record",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                                "Resource": {"Fn::GetAtt": ["Stream", "Arn"]},
                            }],
                        },
                    }],
                    "Tags": [{"Key": "sim2real-role", "Value": role_name}],
                },
            },
            "Destination": {
                "Type": "AWS::Logs::Destination",
                "Properties": {
                    "DestinationName": dest_name,
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "TargetArn": {"Fn::GetAtt": ["Stream", "Arn"]},
                    "DestinationPolicy": policy,
                    "Tags": [{"Key": "sim2real-destination", "Value": dest_name}],
                },
                "DependsOn": ["Role"],
            },
        },
        "Outputs": {
            "DestRef": {"Value": {"Ref": "Destination"}},
            "DestArn": {"Value": {"Fn::GetAtt": ["Destination", "Arn"]}},
            "StreamArn": {"Value": {"Fn::GetAtt": ["Stream", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })


def _destinations(logs, name):
    """Every destination Logs describes under exactly ``name`` (all pages)."""
    return [d for d in paginate(logs, "describe_destinations", "destinations",
                                DestinationNamePrefix=name) if d["destinationName"] == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Logs destination whose DestinationPolicy is not IAM JSON rolls back.

    Logs refuses the policy and describes no destination under the name, while the same template
    with a valid policy deploys a destination that reads back with that policy.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    good = [ctx.unique_name(f"sim2real-cfn-dstpol-good-{k}") for k in ("", "stream-", "role-")]
    bad = [ctx.unique_name(f"sim2real-cfn-dstpol-bad-{k}") for k in ("", "stream-", "role-")]

    # Positive control: the same template, the one property given a VALID value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-dstpol-goodstack-"),
                           _template(*good, _good_policy(good[0])),
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-dstpol-badstack-"),
                          _template(*bad, "{this is not valid IAM JSON}"),
                          Capabilities=["CAPABILITY_NAMED_IAM"])

    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    partition = good_id.split(":")[1]
    out = stack_outputs(cfn, good_id)
    listed = _destinations(logs, good[0])
    assert [d["destinationName"] for d in listed] == [out["DestRef"]], (
        f"control DescribeDestinations {listed!r} for Ref {out['DestRef']!r}"
    )
    dest_arn = f"arn:{partition}:logs:{ctx.region}:{ctx.account}:destination:{good[0]}"
    got = (listed[0]["arn"], listed[0]["targetArn"], listed[0]["roleArn"],
           json.loads(listed[0]["accessPolicy"]))
    want = (dest_arn, out["StreamArn"], out["RoleArn"], _policy(ctx.account, dest_arn))
    assert got == want, f"control destination (arn, target, role, policy) {got!r}"

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Destination")
    got = handler_reason(reason, ctx.account, *bad)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Logs, by the name the destination would have, BEFORE this deletes.
    remaining = _destinations(logs, bad[0])
    assert remaining == [], f"the rolled-back destination is listed: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
