"""s3-upload-lambda-putevents-blocked-without-events-permission."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-upload-lambda-putevents-blocked-without-events-permission"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without events:PutEvents on its role, the S3-triggered Lambda's PutEvents call fails
    and the downstream rule never fires; granting the permission (positive control) unblocks it."""
    event_source = ctx.unique_name("sim2real.blocked.")
    bucket = _create_bucket(ctx)
    account_id = _account_id(ctx)

    role_name, lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        managed_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    handler_code = """
import boto3, json, os

def handler(event, context):
    events = boto3.client("events")
    record = event["Records"][0]["s3"]
    bucket = record["bucket"]["name"]
    key = record["object"]["key"]
    try:
        events.put_events(Entries=[{
            "Source": os.environ["EVENT_SOURCE"],
            "DetailType": "ObjectProcessed",
            "Detail": json.dumps({"bucket": bucket, "key": key}),
        }])
        return {"put_events": "ok"}
    except Exception as e:
        return {"put_events": "failed", "error": str(e)}
"""
    function_arn = _create_function(ctx, lambda_role_arn, handler_code, env={"EVENT_SOURCE": event_source})
    function_name = function_arn.split(":")[-1]
    _allow_s3_invoke(ctx, function_name, f"arn:aws:s3:::{bucket}", account_id)
    _set_bucket_notification(ctx, bucket, function_arn)

    rule_name, rule_arn = _put_rule(ctx, {"source": [event_source]})
    sqs_arn, queue_url = _create_target_queue(ctx, rule_arn)
    _retry_until(
        lambda: _put_targets(ctx, rule_name, [{"Id": "q-target", "Arn": sqs_arn}]),
        retryable_codes=("ValidationException",),
    )

    # --- negative: no events:PutEvents permission, upload should not lead to a matched rule event ---
    key1 = ctx.unique_name("blocked-")
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key1, Body=b"x")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key1))
    messages = _poll_messages(ctx, queue_url, timeout_s=45)
    assert not messages, f"rule fired even though Lambda lacked events:PutEvents permission: {messages}"

    # --- positive control: grant the permission, then the chain event does arrive ---
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-put-events",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}]}
        ),
    )

    found: list[dict[str, Any]] = []
    deadline = time.monotonic() + 90
    attempt = 0
    while time.monotonic() < deadline and not found:
        attempt += 1
        key2 = ctx.unique_name(f"unblocked-{attempt}-")
        s3.put_object(Bucket=bucket, Key=key2, Body=b"y")
        ctx.on_cleanup(lambda k=key2: s3.delete_object(Bucket=bucket, Key=k))
        found = _poll_messages(ctx, queue_url, timeout_s=15)
        if found:
            body = json.loads(found[0]["Body"])
            assert body["detail"]["key"] == key2, f"expected delivered detail.key {key2!r}, got {body['detail'].get('key')!r}"
            break
    assert found, "granting events:PutEvents was never followed by a matched rule event (positive control failed)"


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
) -> tuple[str, str]:
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
    return role_name, role["Arn"]


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


def _create_function(ctx, role_arn: str, code: str, timeout: int = 30, env: dict[str, str] | None = None) -> str:
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
            Environment={"Variables": env or {}},
            Tags={"sim2real": CHECK},
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
    # us-east-1 is S3's default region: create_bucket rejects an explicit LocationConstraint there
    # and requires one everywhere else.
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


def _put_rule(ctx, pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-rule-")
    resp = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, Force=True))
    return name, resp["RuleArn"]


def _put_targets(ctx, rule_name: str, targets: list[dict[str, Any]]) -> None:
    events = ctx.client("events")
    resp = events.put_targets(Rule=rule_name, Targets=targets)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failed: {resp}")
    ids = [t["Id"] for t in targets]
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=ids, Force=True))


def _create_target_queue(ctx, rule_arn: str) -> tuple[str, str]:
    """An SQS queue as the rule target lets us observe delivery without a second Lambda."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return arn, url


def _poll_messages(ctx, queue_url: str, timeout_s: float = 45.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    out: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if out:
            return out
    return out


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
