"""eventbridge-fanout-single-event-invokes-lambda-and-sfn."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-fanout-single-event-invokes-lambda-and-sfn"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single PutEvents call with a rule that has both a Lambda target and a Step Functions
    target invokes the Lambda AND starts the state machine execution from the same event."""
    bucket = _create_bucket(ctx)
    event_source = ctx.unique_name("sim2real.fanout.")

    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"}],
        },
        managed_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    handler_code = f"""
import boto3, json

def handler(event, context):
    s3 = boto3.client("s3")
    detail = event["detail"]
    s3.put_object(Bucket="{bucket}", Key=detail["marker_key"], Body=json.dumps(detail).encode())
    return {{"ok": True}}
"""
    function_arn = _create_function(ctx, lambda_role_arn, handler_code)
    function_name = function_arn.split(":")[-1]

    sfn_role_arn = _create_role(ctx, "states.amazonaws.com")
    sm_arn = _create_state_machine(
        ctx, sfn_role_arn, {"StartAt": "Echo", "States": {"Echo": {"Type": "Pass", "End": True}}}
    )

    rule_name, rule_arn = _put_rule(ctx, {"source": [event_source]})
    _allow_events_invoke(ctx, function_name, rule_arn)
    target_role_arn = _create_role(
        ctx,
        "events.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
        },
    )
    _retry_until(
        lambda: _put_targets(
            ctx,
            rule_name,
            [
                {"Id": "lambda-target", "Arn": function_arn},
                {"Id": "sfn-target", "Arn": sm_arn, "RoleArn": target_role_arn},
            ],
        ),
        retryable_codes=("ValidationException",),
    )

    marker_key = ctx.unique_name("marker-")
    events = ctx.client("events")

    def fire():
        resp = events.put_events(
            Entries=[
                {
                    "Source": event_source,
                    "DetailType": "FanoutTest",
                    "Detail": json.dumps({"marker_key": marker_key, "note": "fanout-single-event"}),
                }
            ]
        )
        assert resp["FailedEntryCount"] == 0

    fire()

    # A rule/target pair this freshly created can race EventBridge's own propagation, so the very
    # first PutEvents can go unmatched with no error at all; re-fire the same event until the
    # Lambda target is confirmed delivered, the same bounded pattern used below for the SFN leg.
    obj = _fire_until(
        fire, lambda: _wait_for_object(ctx, bucket, marker_key, timeout_s=10), timeout_s=60, interval_s=10
    )
    assert obj is not None, "Lambda target was never invoked by the fan-out event"
    body = json.loads(obj["Body"].read())
    assert body["marker_key"] == marker_key

    # EventBridge does not retry an AccessDeniedException caused by IAM propagation delay on a
    # just-created target role, so re-fire the same event until the SFN target role has propagated.
    executions = _fire_until(
        fire, lambda: _wait_executions(ctx, sm_arn, min_count=1, timeout_s=10), timeout_s=120, interval_s=10
    )
    assert executions, "Step Functions target was never started by the fan-out event"
    execution = _wait_for_terminal(ctx, executions[0]["executionArn"], timeout_s=60)
    assert execution["status"] == "SUCCEEDED"
    input_payload = json.loads(execution["input"])
    assert input_payload["detail"]["marker_key"] == marker_key


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(
    ctx,
    principal: str,
    inline_policy: dict[str, Any] | None = None,
    managed_arns: list[str] | None = None,
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for arn in managed_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_until(fn, retryable_codes: tuple[str, ...], timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retryable_codes:
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded after retrying for role propagation: {last_err}")


def _create_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _lambda_zip(code)
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    resp = _retry_until(
        lambda: lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=timeout,
            Tags={"sim2real": CHECK},
        ),
        retryable_codes=("InvalidParameterValueException",),
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _allow_events_invoke(ctx, function_name: str, rule_arn: str) -> None:
    lam = ctx.client("lambda")
    sid = ctx.unique_name("eventsinvoke-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=sid))


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=name).get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_for_object(ctx, bucket: str, key: str, timeout_s: float = 60.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return s3.get_object(Bucket=bucket, Key=key)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                time.sleep(3)
            else:
                raise
    return None


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    resp = _retry_until(
        lambda: sfn.create_state_machine(
            name=name,
            definition=json.dumps(definition),
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": CHECK}],
        ),
        retryable_codes=("AccessDeniedException",),
    )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _put_rule(ctx, pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-rule-")
    resp = events.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, Force=True))
    return name, resp["RuleArn"]


def _put_targets(ctx, rule_name: str, targets: list[dict[str, Any]]) -> None:
    events = ctx.client("events")
    resp = events.put_targets(Rule=rule_name, Targets=targets)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failed: {resp}")
    ids = [t["Id"] for t in targets]
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=ids, Force=True))


def _fire_until(fire_fn, poll_fn, timeout_s: float = 120.0, interval_s: float = 10.0):
    """Repeatedly re-fires and polls because EventBridge does not retry an AccessDeniedException
    from a just-created target IAM role that hasn't finished propagating; a fresh event must be
    delivered after propagation completes."""
    deadline = time.monotonic() + timeout_s
    result = poll_fn()
    while not result and time.monotonic() < deadline:
        fire_fn()
        time.sleep(interval_s)
        result = poll_fn()
    return result


def _wait_executions(ctx, sm_arn: str, min_count: int = 1, timeout_s: float = 90.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = sfn.list_executions(stateMachineArn=sm_arn).get("executions", [])
        if len(execs) >= min_count:
            return execs
        time.sleep(3)
    return sfn.list_executions(stateMachineArn=sm_arn).get("executions", [])


def _wait_for_terminal(ctx, execution_arn: str, timeout_s: float = 90.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(3)
    raise AssertionError("execution did not reach a terminal state in time")


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
