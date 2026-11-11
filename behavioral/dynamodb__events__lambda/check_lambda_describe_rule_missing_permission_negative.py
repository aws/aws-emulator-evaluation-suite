"""lambda-describe-rule-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-describe-rule-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]

_DESCRIBE_RULE_CODE = """
import boto3

def handler(event, context):
    client = boto3.client("events")
    try:
        resp = client.describe_rule(Name=event["RuleName"], EventBusName=event["EventBusName"])
        return {"ok": True, "Name": resp.get("Name"), "State": resp.get("State")}
    except Exception as e:
        code = None
        message = None
        if hasattr(e, "response"):
            code = e.response.get("Error", {}).get("Code")
            message = e.response.get("Error", {}).get("Message")
        return {"ok": False, "error_code": code, "error_message": message}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Lambda whose role lacks events:DescribeRule gets AccessDeniedException and no
    rule metadata is ever returned in the response body, while a sibling Lambda with
    the permission (positive control, same rule) successfully introspects it."""
    events = ctx.client("events")
    bus_name = ctx.unique_name("sim2real-bus-")
    bus_arn = _create_event_bus(ctx, bus_name)

    rule_name = ctx.unique_name("sim2real-rule-")
    events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": ["sim2real.describe-rule-test"]}),
        State="ENABLED",
        Tags=[{"Key": "simparity:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))

    # Function A: role has ONLY basic execution, no events:DescribeRule.
    no_perm_role_arn = _create_lambda_role(ctx, ctx.unique_name("sim2real-role-noperm-"), inline_policy_doc=None)
    no_perm_fn = ctx.unique_name("sim2real-fn-noperm-")
    _create_lambda_function(ctx, no_perm_fn, no_perm_role_arn, _DESCRIBE_RULE_CODE)

    # Function B: positive control -- role HAS events:DescribeRule on this bus's rules.
    control_role_arn = _create_lambda_role(
        ctx,
        ctx.unique_name("sim2real-role-control-"),
        inline_policy_doc={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "events:DescribeRule",
                    "Resource": bus_arn.rsplit(":event-bus/", 1)[0] + f":rule/{bus_name}/{rule_name}",
                }
            ],
        },
    )
    control_fn = ctx.unique_name("sim2real-fn-control-")
    _create_lambda_function(ctx, control_fn, control_role_arn, _DESCRIBE_RULE_CODE)

    denied_result = _invoke_lambda(ctx, no_perm_fn, {"RuleName": rule_name, "EventBusName": bus_name})
    assert denied_result["ok"] is False, denied_result
    assert denied_result["error_code"] == "AccessDeniedException", denied_result
    _, partition, _, _, account, _ = bus_arn.split(":", 5)
    rule_arn = bus_arn.rsplit(":event-bus/", 1)[0] + f":rule/{bus_name}/{rule_name}"
    no_perm_role_name = no_perm_role_arn.rsplit("/", 1)[1]
    expected_message = (
        f"User: arn:{partition}:sts::{account}:assumed-role/{no_perm_role_name}/{no_perm_fn} "
        f"is not authorized to perform: events:DescribeRule on resource: {rule_arn} "
        "because no identity-based policy allows the events:DescribeRule action"
    )
    assert denied_result["error_message"] == expected_message, denied_result
    assert "Name" not in denied_result, "rule metadata leaked despite the access-denied error"

    # The control's inline policy was just attached; IAM's eventual consistency means the very
    # first invoke can still see the pre-attachment state, so poll instead of asserting once.
    control_result = _poll_until(
        lambda: _invoke_lambda(ctx, control_fn, {"RuleName": rule_name, "EventBusName": bus_name}),
        lambda r: r.get("ok") is True,
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert control_result["ok"] is True, control_result
    assert control_result["Name"] == rule_name, control_result
    assert control_result["State"] == "ENABLED", control_result


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zip_code(module_name: str, code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{module_name}.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, role_name: str, inline_policy_doc: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity:check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn))

    if inline_policy_doc is not None:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(inline_policy_doc)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms"))
    return role_arn


def _create_lambda_function(
    ctx, function_name: str, role_arn: str, code: str, env: dict[str, str] | None = None, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = dict(
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_code("index", code)},
        Timeout=timeout,
        MemorySize=128,
        Tags={"simparity:check": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    deadline = time.monotonic() + 90
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(5)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    lam.get_waiter("function_active").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _invoke_lambda(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised an unhandled error: {body}")
    return body


def _create_event_bus(ctx, name: str) -> str:
    events = ctx.client("events")
    resp = events.create_event_bus(Name=name, Tags=[{"Key": "simparity:check", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=name))
    return resp["EventBusArn"]


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
