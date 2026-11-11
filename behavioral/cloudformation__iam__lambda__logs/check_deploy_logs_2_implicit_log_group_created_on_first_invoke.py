"""deploy-logs-2-implicit-log-group-created-on-first-invoke."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-2-implicit-log-group-created-on-first-invoke"

GROUP = "deploy-implicit-log-group"

SERVICES = ["cloudformation", "iam", "lambda", "logs"]

# Stack A: a Lambda function and its execution role, and NOTHING from AWS::Logs. The role carries
# the AWS-managed basic execution policy, so the function itself is allowed to create its group.
_TEMPLATE_IMPLICIT = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "sim2real: Lambda + role only; the /aws/lambda/<fn> group is left implicit.",
    "Parameters": {"FunctionName": {"Type": "String"}},
    "Resources": {
        "ExecutionRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "ManagedPolicyArns": [
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/service-role/"
                        "AWSLambdaBasicExecutionRole"
                    }
                ],
            },
        },
        "Function": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": {"Ref": "FunctionName"},
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                "Timeout": 30,
                "Code": {
                    "ZipFile": (
                        "def handler(event, context):\n"
                        "    print('SIM2REAL_MARKER ' + event['marker'])\n"
                        "    return {'marker': event['marker'],\n"
                        "            'log_group': context.log_group_name,\n"
                        "            'log_stream': context.log_stream_name}\n"
                    )
                },
            },
        },
    },
    "Outputs": {"FunctionName": {"Value": {"Ref": "Function"}}},
}

# Lambda's documented stream naming: YYYY/MM/DD/[<version>]<32 hex>.
_STREAM_RE = re.compile(r"^\d{4}/\d{2}/\d{2}/\[\$LATEST\][0-9a-f]{32}$")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A stack declaring only a Lambda function and its role leaves the log group to Lambda:
    `/aws/lambda/<fn>` is absent after CREATE_COMPLETE, appears on the first invoke with defaults
    (no retention, no KMS key, STANDARD) holding that invocation's output, and survives the stack.
    """
    logs = ctx.client("logs")
    awslambda = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    function_name = _xname(ctx, "implfn")
    log_group_name = f"/aws/lambda/{function_name}"
    # Registered BEFORE the function exists, so LIFO runs it AFTER the stack delete; it loops
    # because a buffered flush can recreate the group after a single delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group_name))

    stack_name = _xname(ctx, "stk")
    _create_stack(ctx, stack_name, _TEMPLATE_IMPLICIT, {"FunctionName": function_name})
    status = _wait_stack_terminal(cfn, stack_name, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack A ended in {status!r}: {_failed_events(cfn, stack_name)!r}"
    )
    types = sorted(
        r["ResourceType"]
        for r in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    )
    assert types == ["AWS::IAM::Role", "AWS::Lambda::Function"], (
        f"stack A must own exactly a role and a function, owns {types!r}"
    )
    awslambda.get_waiter("function_active_v2").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    # 1. Deploying the function does not create its log group: that happens on first invoke.
    before = _exact_group(logs, log_group_name)
    assert before is None, (
        f"{log_group_name} exists before any invoke ({before!r}); Lambda creates it lazily"
    )

    # 2. Invoke; the first use of the freshly created role is where IAM propagation can bite, so
    #    re-invoke (fresh marker each time) within a bound until the line lands.
    marker, payload, request_id, event = _invoke_until_logged(
        ctx, awslambda, logs, function_name, log_group_name
    )
    assert payload["marker"] == marker, f"function echoed {payload!r}, sent {marker!r}"
    assert payload["log_group"] == log_group_name, (
        f"context.log_group_name is {payload['log_group']!r}, expected {log_group_name!r}"
    )

    # 3. The implicit group carries service defaults, and nothing CloudFormation could have set.
    group = _exact_group(logs, log_group_name)
    assert group is not None, f"{log_group_name} vanished after its events were readable"
    assert group["logGroupName"] == log_group_name, group
    assert "retentionInDays" not in group, (
        f"implicit group has retentionInDays={group.get('retentionInDays')!r}; "
        "Lambda creates it with Never-expire"
    )
    assert "kmsKeyId" not in group, f"implicit group has kmsKeyId={group.get('kmsKeyId')!r}"
    assert group.get("logGroupClass") == "STANDARD", (
        f"implicit group logGroupClass is {group.get('logGroupClass')!r}, expected 'STANDARD'"
    )

    # 4. The marker landed in the exact stream the function reported, and that stream follows
    #    Lambda's naming; the platform START/REPORT lines for this request id sit beside it.
    stream = event["logStreamName"]
    assert stream == payload["log_stream"], (
        f"marker landed in {stream!r}, function reported {payload['log_stream']!r}"
    )
    assert _STREAM_RE.match(stream), f"stream name {stream!r} is not YYYY/MM/DD/[$LATEST]<hex>"
    platform = _poll_until(
        lambda: _stream_messages(logs, log_group_name, stream),
        lambda msgs: any(m.startswith(f"REPORT RequestId: {request_id}") for m in msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"REPORT line for {request_id} in {stream}",
    )
    assert any(m.startswith(f"START RequestId: {request_id}") for m in platform), (
        f"no START line for {request_id} in {stream}: {platform[:10]!r}"
    )

    # 5. Ownership: the stack never declared the group, so deleting the stack leaves it intact.
    _delete_stack_and_wait(ctx, stack_name, timeout_s=600.0)
    try:
        awslambda.get_function(FunctionName=function_name)
        raise AssertionError(f"{function_name} still exists after its stack was deleted")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"get_function after delete raised {code!r}"
        message = exc.response["Error"].get("Message", "")
        expected_message = (
            f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
        )
        assert message == expected_message, f"get_function message {message!r} != {expected_message!r}"
    after = _exact_group(logs, log_group_name)
    assert after is not None, (
        f"{log_group_name} was deleted with a stack that never declared it"
    )
    assert after["creationTime"] == group["creationTime"], (
        f"group was recreated: creationTime {group['creationTime']!r} -> {after['creationTime']!r}"
    )
    survived = logs.filter_log_events(
        logGroupName=log_group_name, logStreamNames=[stream], filterPattern=f'"{marker}"'
    ).get("events", [])
    assert any(marker in e["message"] for e in survived), (
        f"marker {marker!r} no longer readable from {stream} after the stack delete"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")},
    ]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _exact_group(logs, name: str) -> dict | None:
    """The one log group whose name is exactly `name` (prefix listing, paginated)."""
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page.get("logGroups", []):
            if g["logGroupName"] == name:
                return g
    return None


def _stream_messages(logs, group: str, stream: str) -> list[str]:
    try:
        resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise
    return [e["message"] for e in resp.get("events", [])]


def _invoke_until_logged(ctx, awslambda, logs, function_name, group, *, attempts=4, wait_s=60.0):
    """Invoke with a fresh marker until that marker is readable in `group`. Bounded: a missing
    line after every attempt is a FAIL naming the last state observed."""
    last = None
    for _ in range(attempts):
        marker = ctx.unique_name("m-")
        resp = awslambda.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"marker": marker}).encode(),
        )
        body = resp["Payload"].read().decode()
        assert not resp.get("FunctionError"), f"{function_name} raised: {body}"
        request_id = resp["ResponseMetadata"]["HTTPHeaders"]["x-amzn-requestid"]
        payload = json.loads(body)
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            try:
                events = logs.filter_log_events(
                    logGroupName=group, filterPattern=f'"{marker}"'
                ).get("events", [])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                events = []
            hit = [e for e in events if f"SIM2REAL_MARKER {marker}" in e["message"]]
            if hit:
                return marker, payload, request_id, hit[0]
            last = events
            time.sleep(5.0)
    raise AssertionError(
        f"no SIM2REAL_MARKER line reached {group} after {attempts} invokes; last {last!r}"
    )


def _create_stack(ctx, name: str, template: dict, parameters: dict) -> None:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=600.0))


def _wait_stack_terminal(cfn, name: str, *, timeout_s: float) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"stack {name} terminal",
    )


def _failed_events(cfn, name: str) -> list:
    events = cfn.describe_stack_events(StackName=name)["StackEvents"]
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ]


def _delete_stack_and_wait(ctx, name: str, *, timeout_s: float = 600.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc):
                return "GONE"
            raise

    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"delete stack {name}",
    )
    if status == "DELETE_FAILED":
        raise RuntimeError(f"stack {name} DELETE_FAILED: {_failed_events(cfn, name)!r}")


def _reap_log_group(logs, name: str, *, rounds: int = 4, settle_s: float = 15.0) -> None:
    """Delete `name`, then watch for a late flush recreating it; re-delete within a bound and
    raise rather than hang if it never converges."""
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(f"delete_log_group {name}: {exc}") from exc
        time.sleep(settle_s)
        if _exact_group(logs, name) is None:
            return
    raise RuntimeError(f"log group {name} kept reappearing after {rounds} deletes")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
