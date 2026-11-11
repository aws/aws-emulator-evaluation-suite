"""lambda-sdk-events-describerule-missing-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-events-describerule-missing-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]

_HANDLER = """
import boto3

def handler(event, context):
    client = boto3.client('events')
    try:
        resp = client.describe_rule(Name=event['rule_name'], EventBusName=event['bus_name'])
        return {'ok': True, 'state': resp.get('State'), 'arn': resp.get('Arn')}
    except Exception as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code', str(e))
        return {'ok': False, 'code': code}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda role lacking events:DescribeRule is denied when introspecting rule config."""
    events = ctx.client("events")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name, Tags=_MANAGED_TAG_KV)
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": ["sim2real.describe.rule.test"]}),
        State="ENABLED",
        Tags=_MANAGED_TAG_KV,
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))

    denied_role_arn = _create_role(ctx, [], "describe-denied")
    denied_fn = _create_function(ctx, denied_role_arn, _HANDLER, "describe-denied")

    denied_body = _invoke(ctx, denied_fn, {"rule_name": rule_name, "bus_name": bus_name})
    assert denied_body["ok"] is False, (
        f"expected the DescribeRule call to be denied, but the role without events:DescribeRule "
        f"succeeded: {denied_body!r}"
    )
    assert denied_body["code"] == "AccessDeniedException", (
        f"expected error code AccessDeniedException, got {denied_body['code']!r}"
    )
    # effect absent: no rule configuration was disclosed to the caller
    assert "state" not in denied_body, (
        f"rule State leaked into the response despite the access-denied error: {denied_body!r}"
    )
    assert "arn" not in denied_body, (
        f"rule Arn leaked into the response despite the access-denied error: {denied_body!r}"
    )

    # positive control in the same file: a role WITH events:DescribeRule reads it back correctly
    allowed_role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "events:DescribeRule", "Resource": rule_arn}],
        "describe-allowed",
    )
    allowed_fn = _create_function(ctx, allowed_role_arn, _HANDLER, "describe-allowed")
    allowed_body = _poll_until(
        lambda: _invoke(ctx, allowed_fn, {"rule_name": rule_name, "bus_name": bus_name}),
        lambda b: b.get("ok") is True,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert allowed_body["state"] == "ENABLED", (
        f"expected State 'ENABLED' from the permitted role's DescribeRule read, got "
        f"{allowed_body['state']!r}"
    )
    assert allowed_body["arn"] == rule_arn, (
        f"expected Arn {rule_arn!r} from the permitted role's DescribeRule read, got "
        f"{allowed_body['arn']!r}"
    )


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_LOGS_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_MANAGED_TAG_KV = [{"Key": "sim2real:managed", "Value": "true"}]
_MANAGED_TAG_MAP = {"sim2real:managed": "true"}


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_role(ctx: Any, statements: list, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-role-{suffix}-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY, Tags=_MANAGED_TAG_KV)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LOGS_POLICY_ARN)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-under-test",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _zip_handler(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, handler_code: str, suffix: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-behav-fn-{suffix}-")
    zip_bytes = _zip_handler(handler_code)
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags=_MANAGED_TAG_MAP,
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"function {name} never became creatable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return name


def _wait_function_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active within {timeout_s}s")


def _invoke(ctx: Any, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    return json.loads(resp["Payload"].read())


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
