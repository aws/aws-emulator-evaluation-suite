"""cfn-logs-subscription-filter-reads-back-and-forwards-a-matching-event-to-lambda."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-subscription-filter-reads-back-and-forwards-a-matching-event-to-lambda"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "logs"]

_DEADLINE_S = 300.0

_DEST_CODE = (
    "import base64, gzip, json\n"
    "def handler(event, context):\n"
    "    data = json.loads(gzip.decompress(base64.b64decode(event['awslogs']['data'])))\n"
    "    for e in data['logEvents']:\n"
    "        print('SIM2REAL_SF_RECEIVED ' + e['message'])\n"
    "    return {'ok': True}\n"
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


def _failures(cfn, stack_id: str) -> list:
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
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


def _template(group: str, fn: str, filter_name: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SrcGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": group, "RetentionInDays": 1},
            },
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow",
                                       "Principal": {"Service": "lambda.amazonaws.com"},
                                       "Action": "sts:AssumeRole"}],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "DstFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn,
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": _DEST_CODE},
                    "Timeout": 15,
                },
            },
            "DstPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "DstFunction"},
                    "Principal": "logs.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["SrcGroup", "Arn"]},
                    "SourceAccount": {"Ref": "AWS::AccountId"},
                },
            },
            "SubFilter": {
                "Type": "AWS::Logs::SubscriptionFilter",
                "DependsOn": "DstPermission",
                "Properties": {
                    "LogGroupName": {"Ref": "SrcGroup"},
                    "FilterName": filter_name,
                    "FilterPattern": "MARKER",
                    "DestinationArn": {"Fn::GetAtt": ["DstFunction", "Arn"]},
                },
            },
        },
    }


@tags("axis:happy-path", "cap:c2", "concern:deploy", "concern:representation",
      "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation AWS::Logs::SubscriptionFilter to a Lambda function reads back its pattern
    and destination through Logs and forwards a matching event to the function; the stack delete
    removes the filter's group, the function and its role.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-subscriptionfilter.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-cfn-sf-group-")
    fn = ctx.unique_name("sim2real-cfn-sf-dst-")
    filter_name = ctx.unique_name("sim2real-cfn-sf-filter-")
    stack = ctx.unique_name("sim2real-cfn-sf-")

    # Registered before the stack so LIFO runs it AFTER the stack teardown deletes the function:
    # CloudFormation never removes the /aws/lambda/<fn> log group Lambda creates on invocation.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(_template(group, fn, filter_name)),
        Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack} ended {status}: {_failures(cfn, stack_id)!r}"

    physical_id = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="SubFilter")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert physical_id == filter_name, (
        f"SubscriptionFilter physical id is {physical_id!r}, expected {filter_name!r}")

    expected_dest_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    described = logs.describe_subscription_filters(logGroupName=group, filterNamePrefix=filter_name)
    filters = described["subscriptionFilters"]
    assert len(filters) == 1, f"expected exactly one subscription filter, got {filters!r}"
    (sf,) = filters
    assert sf["filterPattern"] == "MARKER", f"filterPattern read back as {sf['filterPattern']!r}"
    assert sf["destinationArn"] == expected_dest_arn, (
        f"destinationArn read back as {sf['destinationArn']!r}, expected {expected_dest_arn!r}")

    marker = ctx.unique_name("sim2real-marker-")
    stream = ctx.unique_name("sim2real-sf-stream-")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    start_ms = int(time.time() * 1000)
    logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=[
        {"timestamp": start_ms, "message": f"MARKER {marker}"}])

    dst_group = f"/aws/lambda/{fn}"

    def _received():
        try:
            resp = logs.filter_log_events(
                logGroupName=dst_group, startTime=start_ms - 5000, filterPattern=f'"{marker}"')
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise
        return resp.get("events", [])

    received = _poll(_received, lambda evs: len(evs) > 0, timeout_s=120.0, interval_s=2.0,
                      what="destination function invocation for the matching log event")
    delivered = [e["message"].strip() for e in received]
    assert set(delivered) == {f"SIM2REAL_SF_RECEIVED MARKER {marker}"}, (
        f"the function logged {delivered!r}, expected the forwarded event's message")

    role_name = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="ExecRole")[
        "StackResourceDetail"]["PhysicalResourceId"]

    _teardown_stack(cfn, stack_id)
    code, message = _error(
        lambda: logs.describe_subscription_filters(logGroupName=group, filterNamePrefix=filter_name))
    assert code == "ResourceNotFoundException", (
        f"describing subscription filters on the deleted group returned {code!r}, "
        f"expected ResourceNotFoundException")
    expected = "The specified log group does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    got = _error(lambda: ctx.client("lambda").get_function(FunctionName=fn))
    assert got == ("ResourceNotFoundException", f"Function not found: {expected_dest_arn}"), (
        f"GetFunction on the destination after the stack delete: {got!r}")
    got = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the execution role after the stack delete: {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
