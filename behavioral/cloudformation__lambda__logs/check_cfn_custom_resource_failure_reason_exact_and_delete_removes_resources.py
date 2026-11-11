"""cfn-custom-resource-failure-reason-exact-and-delete-removes-resources."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-custom-resource-failure-reason-exact-and-delete-removes-resources"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "logs"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A FAILED Create's Reason lands verbatim in the rollback event, and both the automatic
    rollback and an explicit stack delete invoke the Lambda with RequestType Delete, leaving
    neither the function nor its log group behind.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    lam = ctx.client("lambda")

    # ---- negative leg: Create responds FAILED with a known Reason ----
    fail_fn = ctx.unique_name("sim2real-xsvc-cr-fail-")
    fail_group = f"/aws/lambda/{fail_fn}"
    fail_reason = ctx.unique_name("sim2real-xsvc-explicit-failure-")
    fail_stack = _create_stack(
        ctx,
        _template(),
        parameters={"FunctionName": fail_fn, "ForceFail": "true", "FailReason": fail_reason},
    )

    status = _wait_terminal(cfn, fail_stack)
    assert status == "ROLLBACK_COMPLETE", (
        f"a Create that answers FAILED must roll the stack back to ROLLBACK_COMPLETE, got {status!r}"
    )

    events = _stack_events(cfn, fail_stack)
    cr_failed = next(
        (e for e in events if e["LogicalResourceId"] == "Signal" and e["ResourceStatus"] == "CREATE_FAILED"),
        None,
    )
    assert cr_failed is not None, (
        f"no CREATE_FAILED event for Signal in {fail_stack}; statuses: "
        f"{[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]!r}"
    )
    # CloudFormation wraps a custom resource's FAILED Reason in a fixed template, carrying the
    # handler's own Reason text verbatim and appending the invocation's own AWS-minted RequestId;
    # the literal wrapping is pinned exactly and the RequestId graded by form only.
    reason = cr_failed.get("ResourceStatusReason") or ""
    match = re.fullmatch(
        r"Received response status \[FAILED\] from custom resource\. Message returned: "
        rf"{re.escape(fail_reason)} \(RequestId: "
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)",
        reason,
    )
    assert match is not None, (
        f"Signal's CREATE_FAILED reason is {reason!r}, expected it to wrap the handler's own "
        f"Reason {fail_reason!r} verbatim with CloudFormation's fixed FAILED-response template"
    )

    # The rollback must have invoked the SAME Lambda with RequestType Delete, not merely
    # dropped the resource from the stack's record.
    _poll_for_log_line(
        logs, fail_group, '"RequestType": "Delete"', timeout_s=180.0,
        description=f"Delete invocation of {fail_fn} during rollback",
    )

    _delete_stack_and_wait(ctx, fail_stack)
    _reap_log_group(logs, fail_group)

    # ---- positive control: Create succeeds; an explicit stack delete removes everything ----
    ok_fn = ctx.unique_name("sim2real-xsvc-cr-ok-")
    ok_group = f"/aws/lambda/{ok_fn}"
    ok_stack = _create_stack(
        ctx,
        _template(),
        parameters={"FunctionName": ok_fn, "ForceFail": "false", "FailReason": "unused"},
    )

    status = _wait_terminal(cfn, ok_stack)
    assert status == "CREATE_COMPLETE", f"positive control expected CREATE_COMPLETE, got {status!r}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=ok_stack)["Stacks"][0].get("Outputs", [])
    }
    fn_arn = outputs["FunctionArn"]
    lam.get_function(FunctionName=ok_fn)  # must not raise: the function really exists

    _delete_stack_and_wait(ctx, ok_stack)

    # The explicit delete invoked the Lambda with RequestType Delete too (CFN will not reach
    # DELETE_COMPLETE for a custom resource until that Lambda PUTs its SUCCESS response).
    _poll_for_log_line(
        logs, ok_group, '"RequestType": "Delete"', timeout_s=180.0,
        description=f"Delete invocation of {ok_fn} during stack delete",
    )

    code, message = _error(lambda: lam.get_function(FunctionName=ok_fn))
    want = f"Function not found: {fn_arn}"
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted function, got {code!r}: {message!r}"
    )
    assert message == want, f"GetFunction message {message!r} != expected {want!r}"

    _reap_log_group(logs, ok_group)
    remaining = logs.describe_log_groups(logGroupNamePrefix=ok_group)["logGroups"]
    assert not any(g["logGroupName"] == ok_group for g in remaining), (
        f"log group {ok_group!r} still present after reaping: {remaining!r}"
    )


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "FunctionName": {"Type": "String"},
            "ForceFail": {"Type": "String", "AllowedValues": ["true", "false"]},
            "FailReason": {"Type": "String", "Default": "unused"},
        },
        "Resources": {
            "ExecRole": {
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
                    "Policies": [
                        {
                            "PolicyName": "AllowLogging",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "ProviderFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "FunctionName"},
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": {"Fn::Join": ["\n", _provider_code_lines()]}},
                },
            },
            "Signal": {
                "Type": "Custom::Sim2RealSignal",
                "Properties": {
                    "ServiceToken": {"Fn::GetAtt": ["ProviderFunction", "Arn"]},
                    "ForceFail": {"Ref": "ForceFail"},
                    "FailReason": {"Ref": "FailReason"},
                },
            },
        },
        "Outputs": {
            "FunctionArn": {"Value": {"Fn::GetAtt": ["ProviderFunction", "Arn"]}},
        },
    }


def _provider_code_lines() -> list[str]:
    return [
        "import json",
        "import urllib.request",
        "",
        "def handler(event, context):",
        "    props = event.get('ResourceProperties') or {}",
        "    request_type = event['RequestType']",
        "    physical_id = event.get('PhysicalResourceId') or (",
        "        'sim2real-xsvc-cr-' + context.aws_request_id[:12])",
        "    print(json.dumps({'RequestType': request_type, 'PhysicalResourceId': physical_id}))",
        "    status = 'SUCCESS'",
        "    reason = 'sim2real responder ok'",
        "    if request_type == 'Create' and props.get('ForceFail') == 'true':",
        "        status = 'FAILED'",
        "        reason = props.get('FailReason') or 'sim2real-xsvc-custom-resource-refused'",
        "    body = json.dumps({",
        "        'Status': status,",
        "        'Reason': reason,",
        "        'PhysicalResourceId': physical_id,",
        "        'StackId': event['StackId'],",
        "        'RequestId': event['RequestId'],",
        "        'LogicalResourceId': event['LogicalResourceId'],",
        "        'Data': {},",
        "    }).encode()",
        "    req = urllib.request.Request(",
        "        url=event['ResponseURL'], data=body, method='PUT', headers={'Content-Type': ''}",
        "    )",
        "    urllib.request.urlopen(req, timeout=10)",
    ]


# ===== helpers =====


def _error(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _poll_for_log_line(logs, log_group, needle, *, timeout_s=180.0, interval_s=3.0, description="log line"):
    """Poll ``log_group`` until some event message contains ``needle``; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last_messages: list[str] = []
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
            continue
        last_messages = [e["message"] for e in resp.get("events", [])]
        if any(needle in m for m in last_messages):
            return last_messages
        time.sleep(interval_s)
    raise AssertionError(
        f"{description}: no line containing {needle!r} in {log_group} within {timeout_s}s; "
        f"saw {last_messages!r}"
    )


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
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
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise


def _wait_terminal(cfn, name: str, *, timeout_s: float = 300.0) -> str:
    return _poll_until(
        lambda: _stack_status(cfn, name),
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name} terminal",
    )


def _stack_events(cfn, stack_name: str) -> list[dict[str, Any]]:
    """Every DescribeStackEvents page for a stack, oldest first."""
    events: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackName": stack_name}
        if token:
            kwargs["NextToken"] = token
        resp = cfn.describe_stack_events(**kwargs)
        events.extend(resp.get("StackEvents", []))
        token = resp.get("NextToken")
        if not token:
            break
    return list(reversed(events))


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )
    if status not in {"DELETE_COMPLETE", "GONE"}:
        raise AssertionError(f"stack {stack_name} ended in {status}, expected DELETE_COMPLETE")


def _create_stack(ctx, template: dict[str, Any], *, parameters: dict[str, str]) -> str:
    """CreateStack; register delete-and-reap teardowns right away; return the stack name."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-xsvc-cr-stk-")
    fn_name = parameters["FunctionName"]
    cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{fn_name}"))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
