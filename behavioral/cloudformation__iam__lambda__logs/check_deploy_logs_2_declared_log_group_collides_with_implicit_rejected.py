"""deploy-logs-2-declared-log-group-collides-with-implicit-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-2-declared-log-group-collides-with-implicit-rejected"

GROUP = "deploy-implicit-log-group"

SERVICES = ["cloudformation", "iam", "lambda", "logs"]

_ROLE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

_CODE = (
    "def handler(event, context):\n"
    "    print('SIM2REAL_MARKER ' + event['marker'])\n"
    "    return {'marker': event['marker'],\n"
    "            'log_group': context.log_group_name,\n"
    "            'log_stream': context.log_stream_name}\n"
)

# Pre-step stack: Lambda + role only. Its first invoke creates /aws/lambda/<fn> implicitly.
_TEMPLATE_IMPLICIT = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "sim2real: Lambda + role only; the /aws/lambda/<fn> group is left implicit.",
    "Parameters": {"FunctionName": {"Type": "String"}},
    "Resources": {
        "ExecutionRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": _ROLE_TRUST,
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
                "Code": {"ZipFile": _CODE},
            },
        },
    },
}

# Stack B AND the positive control: the same template. Lambda + role + an explicitly declared
# AWS::Logs::LogGroup at the implicit name, with RetentionInDays 3, and the function DependsOn
# the group. The role may NOT create groups, so control-side events prove the declared group is
# the one Lambda writes into.
_TEMPLATE_DECLARED = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "sim2real: Lambda + role + DependsOn-ordered /aws/lambda/<fn> log group.",
    "Parameters": {"FunctionName": {"Type": "String"}},
    "Resources": {
        "LogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": {"Fn::Sub": "/aws/lambda/${FunctionName}"},
                "RetentionInDays": 3,
            },
        },
        "ExecutionRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": _ROLE_TRUST,
                "Policies": [
                    {
                        "PolicyName": "declared-group-write-only",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                                    "Resource": {
                                        "Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:"
                                        "${AWS::AccountId}:log-group:/aws/lambda/"
                                        "${FunctionName}:*"
                                    },
                                }
                            ],
                        },
                    }
                ],
            },
        },
        "Function": {
            "Type": "AWS::Lambda::Function",
            "DependsOn": "LogGroup",
            "Properties": {
                "FunctionName": {"Ref": "FunctionName"},
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                "Timeout": 30,
                "Code": {"ZipFile": _CODE},
            },
        },
    },
    "Outputs": {"LogGroupName": {"Value": {"Ref": "LogGroup"}}},
}


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Declaring AWS::Logs::LogGroup at an implicitly created /aws/lambda/<fn> fails validation with
    NAME_CONFLICT_VALIDATION and rolls back leaving the existing group untouched; the same template
    with no prior group deploys, sets RetentionInDays 3, and is deleted with the stack.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-loggroup.html
    """
    logs = ctx.client("logs")
    awslambda = ctx.client("lambda")
    cfn = ctx.client("cloudformation")

    collide_fn = _xname(ctx, "collfn")
    collide_group = f"/aws/lambda/{collide_fn}"
    control_fn = _xname(ctx, "ctrlfn")
    control_group = f"/aws/lambda/{control_fn}"
    # Registered before either function exists so LIFO runs them after every stack delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, collide_group))
    ctx.on_cleanup(lambda: _reap_log_group(logs, control_group))

    # Kick off the pre-step stack and the positive-control stack together; both are independent.
    pre_stack = _xname(ctx, "stk")
    _create_stack(ctx, pre_stack, _TEMPLATE_IMPLICIT, {"FunctionName": collide_fn})
    control_stack = _xname(ctx, "stk")
    _create_stack(ctx, control_stack, _TEMPLATE_DECLARED, {"FunctionName": control_fn})

    # ---- Pre-step: the function creates its group implicitly on first invoke. ----------------
    status = _wait_stack_terminal(cfn, pre_stack, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"pre-step stack ended in {status!r}: {_failed_events(cfn, pre_stack)!r}"
    )
    awslambda.get_waiter("function_active_v2").wait(FunctionName=collide_fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    pre_marker, pre_payload, pre_request, pre_event = _invoke_until_logged(
        ctx, awslambda, logs, collide_fn, collide_group
    )
    pre_stream = pre_event["logStreamName"]
    assert pre_payload["log_group"] == collide_group, pre_payload
    _poll_until(
        lambda: _stream_messages(logs, collide_group, pre_stream),
        lambda msgs: any(m.startswith(f"REPORT RequestId: {pre_request}") for m in msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"REPORT line for {pre_request} flushed to {pre_stream}",
    )
    original = _exact_group(logs, collide_group)
    assert original is not None, f"{collide_group} absent although its events were readable"
    assert "retentionInDays" not in original, original

    # The pre-step function must be gone so the colliding stack can own the same function name;
    # the implicit group it created stays behind, which is exactly the trap under test.
    _delete_stack_and_wait(ctx, pre_stack, timeout_s=600.0)
    assert _exact_group(logs, collide_group) is not None, (
        f"{collide_group} disappeared with the pre-step stack that never declared it"
    )

    # ---- Stack B: declare the group that already exists. -------------------------------------
    collide_stack = _xname(ctx, "stk")
    _create_stack(ctx, collide_stack, _TEMPLATE_DECLARED, {"FunctionName": collide_fn})
    status = _wait_stack_terminal(cfn, collide_stack, timeout_s=900.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"colliding stack ended in {status!r}, expected 'ROLLBACK_COMPLETE': "
        f"{_failed_events(cfn, collide_stack)!r}"
    )
    # Real AWS refuses this BEFORE provisioning anything: the collision is caught by
    # CloudFormation's pre-deployment validation, so the stack itself goes CREATE_FAILED with
    # DetailedStatus VALIDATION_FAILED and no resource ever enters CREATE_IN_PROGRESS.
    events = _all_stack_events(cfn, collide_stack)
    summary = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("DetailedStatus"),
         e.get("ResourceStatusReason"))
        for e in events
    ]
    stack_failed = [
        e for e in events
        if e["LogicalResourceId"] == collide_stack and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(stack_failed) == 1, f"expected one stack-level CREATE_FAILED: {summary!r}"
    assert stack_failed[0].get("DetailedStatus") == "VALIDATION_FAILED", (
        f"stack CREATE_FAILED DetailedStatus is {stack_failed[0].get('DetailedStatus')!r}, "
        f"expected 'VALIDATION_FAILED': {summary!r}"
    )
    provisioned = sorted({e["LogicalResourceId"] for e in events} - {collide_stack})
    assert provisioned == [], (
        f"resources {provisioned!r} were touched although validation failed first: {summary!r}"
    )
    failures = _all_operation_events(cfn, collide_stack)
    detail = [
        (e.get("EventType"), e.get("LogicalResourceId"), e.get("ResourceType"),
         e.get("ValidationName"), e.get("ValidationStatus"), e.get("ValidationStatusReason"),
         e.get("ValidationPath"))
        for e in failures
    ]
    lg_errors = [
        e for e in failures
        if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "LogGroup"
    ]
    assert len(lg_errors) == 1, f"expected one LogGroup VALIDATION_ERROR: {detail!r}"
    lg_error = lg_errors[0]
    assert lg_error.get("ResourceType") == "AWS::Logs::LogGroup", detail
    assert lg_error.get("ValidationStatus") == "FAILED", detail
    assert lg_error.get("ValidationName") == "NAME_CONFLICT_VALIDATION", detail
    assert lg_error.get("ValidationPath") == "/Resources/LogGroup", detail
    expected_reason = (
        f"Resource of type 'AWS::Logs::LogGroup' with identifier '{collide_group}' already exists."
    )
    assert lg_error.get("ValidationStatusReason") == expected_reason, (
        f"validation reason {lg_error.get('ValidationStatusReason')!r} != {expected_reason!r}"
    )
    others = [e for e in failures if e.get("EventType") == "VALIDATION_ERROR" and e is not lg_error]
    assert not others, f"validation flagged more than the colliding group: {detail!r}"
    try:
        awslambda.get_function(FunctionName=collide_fn)
        raise AssertionError(f"{collide_fn} exists although its stack rolled back")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"get_function raised {code!r}"
        message = exc.response["Error"].get("Message", "")
        expected_message = (
            f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{collide_fn}"
        )
        assert message == expected_message, f"get_function message {message!r} != {expected_message!r}"

    # The pre-existing group is untouched: same identity, still no retention, events intact.
    after = _exact_group(logs, collide_group)
    assert after is not None, f"the rollback deleted {collide_group}, which the stack never owned"
    assert after["creationTime"] == original["creationTime"], (
        f"{collide_group} was recreated: {original['creationTime']!r} -> {after['creationTime']!r}"
    )
    assert after["arn"] == original["arn"], (original["arn"], after["arn"])
    assert "retentionInDays" not in after, (
        f"the failed stack applied retentionInDays={after.get('retentionInDays')!r} to a group "
        "it never created"
    )
    survived = _stream_messages(logs, collide_group, pre_stream)
    assert any(f"SIM2REAL_MARKER {pre_marker}" in m for m in survived), (
        f"pre-existing marker {pre_marker!r} lost from {pre_stream}: {survived[:10]!r}"
    )

    # ---- Positive control: the same template with no prior group deploys and works. ----------
    status = _wait_stack_terminal(cfn, control_stack, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended in {status!r}: {_failed_events(cfn, control_stack)!r}"
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=control_stack)["Stacks"][0].get("Outputs", [])
    }
    assert outputs.get("LogGroupName") == control_group, outputs
    declared = _exact_group(logs, control_group)
    assert declared is not None, f"{control_group} absent after CREATE_COMPLETE, before invoke"
    assert declared.get("retentionInDays") == 3, (
        f"declared group retentionInDays is {declared.get('retentionInDays')!r}, expected 3"
    )
    awslambda.get_waiter("function_active_v2").wait(FunctionName=control_fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    ctl_marker, ctl_payload, ctl_request, ctl_event = _invoke_until_logged(
        ctx, awslambda, logs, control_fn, control_group
    )
    assert ctl_event["logStreamName"] == ctl_payload["log_stream"], (ctl_event, ctl_payload)
    _poll_until(
        lambda: _stream_messages(logs, control_group, ctl_event["logStreamName"]),
        lambda msgs: any(m.startswith(f"REPORT RequestId: {ctl_request}") for m in msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"REPORT line for {ctl_request} flushed",
    )
    still = _exact_group(logs, control_group)
    assert still is not None and still["creationTime"] == declared["creationTime"], (
        f"the invoke replaced the declared group: {declared!r} -> {still!r}"
    )
    assert still.get("retentionInDays") == 3, still

    _delete_stack_and_wait(ctx, control_stack, timeout_s=600.0)
    gone = _poll_until(
        lambda: _exact_group(logs, control_group),
        lambda g: g is None,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"{control_group} deleted with its stack",
    )
    assert gone is None, gone


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
    """Invoke with a fresh marker until it is readable in `group`; re-invoking is a bounded retry
    while a freshly created role's permissions propagate."""
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


def _all_stack_events(cfn, name: str) -> list:
    out: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(page.get("StackEvents", []))
    return out


def _all_operation_events(cfn, name: str) -> list:
    """DescribeEvents with FailedEvents=True: the per-issue validation detail for a stack."""
    out: list = []
    kwargs: dict[str, Any] = {"StackName": name, "Filters": {"FailedEvents": True}}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(page.get("OperationEvents", []))
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _failed_events(cfn, name: str) -> list:
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _all_stack_events(cfn, name)
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
