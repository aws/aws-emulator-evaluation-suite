"""cfn-logs-subscription-filter-missing-permission-rejected-at-create."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-subscription-filter-missing-permission-rejected-at-create"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "logs"]

_DEADLINE_S = 300.0

_DEST_CODE = (
    "def handler(event, context):\n"
    "    print('SIM2REAL_SF_RECEIVED')\n"
    "    return {'ok': True}\n"
)

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _error(fn):
    """Call fn(), which AWS must refuse; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _events(cfn, stack_id: str) -> list:
    out: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _failures(cfn, stack_id: str) -> list:
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in _events(cfn, stack_id)
            if e["ResourceStatus"].endswith("_FAILED")]


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 2.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent; a late log
    flush that re-creates the group after the function's delete is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


def _teardown_stack(cfn, stack_id: str) -> None:
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _role(fn_principal: str = "lambda.amazonaws.com") -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": fn_principal},
                               "Action": "sts:AssumeRole"}],
            },
            "ManagedPolicyArns": [
                "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            ],
        },
    }


def _function(name: str, role_logical: str) -> dict:
    return {
        "Type": "AWS::Lambda::Function",
        "Properties": {
            "FunctionName": name,
            "Runtime": "python3.13",
            "Handler": "index.handler",
            "Role": {"Fn::GetAtt": [role_logical, "Arn"]},
            "Code": {"ZipFile": _DEST_CODE},
            "Timeout": 15,
        },
    }


def _good_template(group: str, fn: str, filter_name: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SrcGroup": {"Type": "AWS::Logs::LogGroup",
                         "Properties": {"LogGroupName": group, "RetentionInDays": 1}},
            "Role": _role(),
            "Function": _function(fn, "Role"),
            "Permission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "Function"},
                    "Principal": "logs.amazonaws.com", "SourceArn": {"Fn::GetAtt": ["SrcGroup", "Arn"]},
                    "SourceAccount": {"Ref": "AWS::AccountId"},
                },
            },
            "Filter": {
                "Type": "AWS::Logs::SubscriptionFilter",
                "DependsOn": "Permission",
                "Properties": {
                    "LogGroupName": {"Ref": "SrcGroup"}, "FilterName": filter_name,
                    "FilterPattern": "MARKER", "DestinationArn": {"Fn::GetAtt": ["Function", "Arn"]},
                },
            },
        },
    }


def _bad_template(group: str, fn: str, filter_name: str) -> dict:
    # Same wiring as the good template, minus the AWS::Lambda::Permission: CloudWatch Logs
    # validates execute access at PutSubscriptionFilter time, before any event is published.
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SrcGroup": {"Type": "AWS::Logs::LogGroup",
                         "Properties": {"LogGroupName": group, "RetentionInDays": 1}},
            "Role": _role(),
            "Function": _function(fn, "Role"),
            "Filter": {
                "Type": "AWS::Logs::SubscriptionFilter",
                "DependsOn": "Function",
                "Properties": {
                    "LogGroupName": {"Ref": "SrcGroup"}, "FilterName": filter_name,
                    "FilterPattern": "MARKER", "DestinationArn": {"Fn::GetAtt": ["Function", "Arn"]},
                },
            },
        },
    }


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A SubscriptionFilter to a Lambda with no AWS::Lambda::Permission for logs.amazonaws.com
    fails with Logs' exact error and rolls back; the same wiring with the permission delivers.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    good_group = ctx.unique_name("sim2real-cfn-sfneg-good-group-")
    good_fn = ctx.unique_name("sim2real-cfn-sfneg-good-")
    good_filter = ctx.unique_name("sim2real-cfn-sfneg-goodf-")
    good_stack = ctx.unique_name("sim2real-cfn-sfneg-good-")

    bad_group = ctx.unique_name("sim2real-cfn-sfneg-bad-group-")
    bad_fn = ctx.unique_name("sim2real-cfn-sfneg-bad-")
    bad_filter = ctx.unique_name("sim2real-cfn-sfneg-badf-")
    bad_stack = ctx.unique_name("sim2real-cfn-sfneg-bad-")

    # Positive control first: the correctly permissioned wiring creates and actually delivers.
    # Registered before either stack so LIFO runs it AFTER each stack teardown deletes the
    # functions: CloudFormation never removes the /aws/lambda/<fn> log group Lambda creates on
    # invocation.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{bad_fn}"))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{good_fn}"))
    good_id = cfn.create_stack(
        StackName=good_stack, TemplateBody=json.dumps(_good_template(good_group, good_fn, good_filter)),
        Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, good_id))
    good_status = _settle(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the positive control stack ended {good_status!r}: {_failures(cfn, good_id)!r}")
    good_role = cfn.describe_stack_resource(StackName=good_id, LogicalResourceId="Role")[
        "StackResourceDetail"]["PhysicalResourceId"]

    good_dst_group = f"/aws/lambda/{good_fn}"

    def _invocations(dst_group: str, start_ms: int) -> list:
        try:
            resp = logs.filter_log_events(
                logGroupName=dst_group, startTime=start_ms, filterPattern="SIM2REAL_SF_RECEIVED")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise
        return resp.get("events", [])

    good_stream = ctx.unique_name("sim2real-sfneg-good-stream-")
    logs.create_log_stream(logGroupName=good_group, logStreamName=good_stream)
    start_ms = int(time.time() * 1000)
    marker = ctx.unique_name("sim2real-marker-")
    logs.put_log_events(logGroupName=good_group, logStreamName=good_stream, logEvents=[
        {"timestamp": start_ms, "message": f"MARKER {marker}"}])
    delivered = _poll(lambda: _invocations(good_dst_group, start_ms), lambda evs: len(evs) > 0,
                      timeout_s=120.0, interval_s=2.0, what="positive control's invocation")
    assert delivered, "the permissioned subscription filter never delivered"

    # The broken wiring: identical except for the missing AWS::Lambda::Permission.
    bad_id = cfn.create_stack(
        StackName=bad_stack, TemplateBody=json.dumps(_bad_template(bad_group, bad_fn, bad_filter)),
        Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, bad_id))
    bad_status = _settle(cfn, bad_id)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a subscription filter with no invoke permission ended {bad_status!r}: "
        f"{_failures(cfn, bad_id)!r}"
    )
    reasons = [e.get("ResourceStatusReason", "") for e in _events(cfn, bad_id)
               if e["LogicalResourceId"] == "Filter" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for Filter, got {reasons!r}"
    match = _REASON.match(reasons[0])
    assert match is not None, f"Filter's reason is not a resource-handler message: {reasons[0]!r}"
    got = (match["message"], match["service"], match["status"], match["handler"])
    want = (
        "Invalid request provided: AWS::Logs::SubscriptionFilter. Could not execute the lambda "
        "function. Make sure you have given CloudWatch Logs permission to execute your function.",
        "CloudWatchLogs",
        "400",
        "InvalidRequest",
    )
    assert got == want, f"Filter's CREATE_FAILED reason: expected {want!r}, got {got!r}"

    # Effect absent: the rollback removed the broken stack's group, function and role.
    _assert_stack_resources_gone(ctx, bad_group, bad_fn)

    for stack_id in (bad_id, good_id):
        _teardown_stack(cfn, stack_id)
        status = _status(cfn, stack_id)
        assert status == "DELETE_COMPLETE", f"stack {stack_id} after the delete is {status!r}"
    _assert_stack_resources_gone(ctx, good_group, good_fn)
    got = _error(lambda: ctx.client("iam").get_role(RoleName=good_role))
    assert got == ("NoSuchEntity", f"The role with name {good_role} cannot be found."), (
        f"GetRole on the control's execution role after its stack delete: {got!r}")


def _assert_stack_resources_gone(ctx, group: str, fn: str) -> None:
    """The stack's log group and destination function answer their exact not-found errors."""
    got = _error(lambda: ctx.client("logs").describe_subscription_filters(logGroupName=group))
    assert got == ("ResourceNotFoundException", "The specified log group does not exist."), (
        f"DescribeSubscriptionFilters on {group!r}: {got!r}")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    got = _error(lambda: ctx.client("lambda").get_function(FunctionName=fn))
    assert got == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction({fn!r}): {got!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
