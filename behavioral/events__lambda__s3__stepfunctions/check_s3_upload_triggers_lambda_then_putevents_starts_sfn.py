"""s3-upload-triggers-lambda-then-putevents-starts-sfn."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-upload-triggers-lambda-then-putevents-starts-sfn"
GROUP = "event-chain"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 object-created -> Lambda -> PutEvents -> rule match -> SFN execution, end to end."""
    event_source = ctx.unique_name("sim2real.s3chain.")
    bucket = _create_bucket(ctx)
    account_id = _account_id(ctx)

    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
        },
        managed_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    handler_code = f"""
import boto3, json, os

def handler(event, context):
    events = boto3.client("events")
    record = event["Records"][0]["s3"]
    bucket = record["bucket"]["name"]
    key = record["object"]["key"]
    events.put_events(Entries=[{{
        "Source": "{event_source}",
        "DetailType": "ObjectProcessed",
        "Detail": json.dumps({{"bucket": bucket, "key": key}}),
    }}])
    return {{"bucket": bucket, "key": key}}
"""
    function_arn = _create_function(ctx, lambda_role_arn, handler_code)
    function_name = function_arn.split(":")[-1]
    _allow_s3_invoke(ctx, function_name, f"arn:aws:s3:::{bucket}", account_id)
    _set_bucket_notification(ctx, bucket, function_arn)

    sfn_role_arn = _create_role(ctx, "states.amazonaws.com")
    sm_arn = _create_state_machine(
        ctx,
        sfn_role_arn,
        {"StartAt": "Echo", "States": {"Echo": {"Type": "Pass", "End": True}}},
    )

    rule_name, rule_arn = _put_rule(ctx, {"source": [event_source]})
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
            [{"Id": "sfn-target", "Arn": sm_arn, "RoleArn": target_role_arn}],
        ),
        retryable_codes=("ValidationException",),
    )

    key = ctx.unique_name("uploaded-")
    s3 = ctx.client("s3")

    def fire():
        s3.put_object(Bucket=bucket, Key=key, Body=b"hello-chain")

    fire()
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # EventBridge does not retry an AccessDeniedException from a just-created target role that
    # hasn't finished propagating, so re-upload (re-triggering the S3 notification) until the SFN
    # target role has propagated.
    executions = _fire_until(
        fire, lambda: _wait_executions(ctx, sm_arn, min_count=1, timeout_s=10), timeout_s=150, interval_s=10
    )
    assert executions, "no Step Functions execution was started by the S3->Lambda->EventBridge chain"
    execution = _wait_for_terminal(ctx, executions[0]["executionArn"], timeout_s=90)
    assert execution["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {execution['status']} for execution {executions[0]['executionArn']}"
    )
    payload = json.loads(execution["input"])
    assert payload["source"] == event_source, f"expected source {event_source!r}, got {payload.get('source')!r}"
    detail = payload["detail"]
    assert detail["bucket"] == bucket, f"expected bucket {bucket!r}, got {detail.get('bucket')!r}"
    assert detail["key"] == key, f"expected key {key!r}, got {detail.get('key')!r}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
        ),
        retryable_codes=("InvalidParameterValueException",),
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _allow_s3_invoke(ctx, function_name: str, bucket_arn: str, account_id: str) -> None:
    lam = ctx.client("lambda")
    sid = ctx.unique_name("s3invoke-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn=bucket_arn,
        SourceAccount=account_id,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=sid))


def _set_bucket_notification(ctx, bucket: str, function_arn: str) -> None:
    s3 = ctx.client("s3")
    _retry_until(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket,
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {"LambdaFunctionArn": function_arn, "Events": ["s3:ObjectCreated:*"]}
                ]
            },
        ),
        retryable_codes=("InvalidArgument",),
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bkt-").lower().replace("_", "-")
    # us-east-1 rejects an explicit LocationConstraint; every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
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


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    resp = _retry_until(
        lambda: sfn.create_state_machine(
            name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
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


def _fire_until(fire_fn, poll_fn, timeout_s: float = 150.0, interval_s: float = 10.0):
    """Repeatedly re-fires and polls because EventBridge does not retry an AccessDeniedException
    from a just-created target IAM role that hasn't finished propagating; the triggering event
    must be re-fired after the role has propagated."""
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
