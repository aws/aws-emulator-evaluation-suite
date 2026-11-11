"""s3-notification-to-sqs-lambda-esm-drains-queue-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-notification-to-sqs-lambda-esm-drains-queue-positive"
GROUP = "event-propagation"
SERVICES = ["lambda", "s3", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A PutObject on a bucket notifying an SQS queue consumed by a Lambda event source mapping
    reaches the function as the S3 event record inside the SQS body, and the queue then drains
    to 0 visible / 0 in-flight: asynchronous delivery no single API response shows."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx)
    source = _create_queue(ctx)
    _set_queue_policy_for_s3(ctx, source["url"], source["arn"], bucket)

    s3 = ctx.client("s3")
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {
                    "QueueArn": source["arn"],
                    "Events": ["s3:ObjectCreated:Put"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "prefix", "Value": "uploads/"}]}
                    },
                }
            ]
        },
    )

    fn = _create_function(ctx, role_arn, {"REPORT_BUCKET": bucket, "REPORT_PREFIX": "reports/"})
    _create_esm(ctx, fn["name"], source["arn"], batch_size=1)

    key = f"uploads/{ctx.unique_name('item')}.txt"
    body = b"sim2real-s3-sqs-esm-payload"
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    def _matching_report() -> dict[str, Any] | None:
        for obj in s3.list_objects_v2(Bucket=bucket, Prefix="reports/").get("Contents", []):
            report = json.loads(s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read())
            for rec in report.get("records", []):
                if rec.get("key") == key:
                    return rec
        return None

    deadline = time.monotonic() + 120
    record = None
    while time.monotonic() < deadline:
        record = _matching_report()
        if record is not None:
            break
        time.sleep(3)
    assert record is not None, f"no lambda-observed S3 event record for key {key!r} within 120s"
    assert record["bucket"] == bucket, f"expected bucket {bucket!r} in the delivered record, got {record['bucket']!r}"
    assert record["event_name"] == "ObjectCreated:Put", (
        f"expected event name 'ObjectCreated:Put' for a PutObject upload, got {record['event_name']!r}"
    )
    assert record["size"] == len(body), (
        f"expected the delivered record to carry the uploaded size {len(body)}, got {record['size']!r}"
    )

    def _source_drained() -> bool:
        attrs = ctx.client("sqs").get_queue_attributes(
            QueueUrl=source["url"],
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        return (
            int(attrs["ApproximateNumberOfMessages"]) == 0
            and int(attrs["ApproximateNumberOfMessagesNotVisible"]) == 0
        )

    deadline = time.monotonic() + 60
    drained = False
    while time.monotonic() < deadline:
        if _source_drained():
            drained = True
            break
        time.sleep(2)
    assert drained, "source queue never drained to 0 visible / 0 in-flight after the mapping consumed the message"


# ===== helpers =====

_ROLE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
]

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": "sim2real-xsvc"}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


_LAMBDA_CODE = '''
import json
import os
import uuid

import boto3

s3 = boto3.client("s3")
BUCKET = os.environ["REPORT_BUCKET"]
PREFIX = os.environ.get("REPORT_PREFIX", "reports/")


def handler(event, context):
    records = []
    for r in event.get("Records", []):
        body = json.loads(r["body"])
        for s3_rec in body.get("Records", []):
            records.append({
                "bucket": s3_rec["s3"]["bucket"]["name"],
                "key": s3_rec["s3"]["object"]["key"],
                "event_name": s3_rec["eventName"],
                "size": s3_rec["s3"]["object"].get("size"),
            })
    key = PREFIX + context.aws_request_id + "-" + uuid.uuid4().hex[:8] + ".json"
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps({"records": records}).encode("utf-8"))
    return {"batchItemFailures": []}
'''


def _build_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-bkt-")
    # us-east-1 is S3's default region and rejects an explicit LocationConstraint for itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    for obj in s3.list_objects_v2(Bucket=name).get("Contents", []):
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_ROLE_TRUST_POLICY, Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return role_arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    for policy_arn in _MANAGED_POLICIES:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_role(RoleName=name)


def _create_function(ctx, role_arn: str, env: dict[str, str], timeout: int = 30) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    code_zip = _build_zip(_LAMBDA_CODE)
    last_err = None
    resp = None
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    # A new execution role is not assumable by Lambda at once: retry its InvalidParameterValue to a deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (100.0 if left is None else min(100.0, left))
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_zip},
                Timeout=timeout,
                Environment={"Variables": env},
                Tags=_xsvc_resource_tags(),
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx, attributes: dict[str, str] | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-xsvc-q-")
    kwargs: dict[str, Any] = {"QueueName": name, "tags": _xsvc_resource_tags()}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _set_queue_policy_for_s3(ctx, queue_url: str, queue_arn: str, bucket_name: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3Notify",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "SQS:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket_name}"}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _create_esm(ctx, function_name: str, queue_arn: str, batch_size: int = 1) -> str:
    lam = ctx.client("lambda")
    esm_uuid = lam.create_event_source_mapping(
        EventSourceArn=queue_arn, FunctionName=function_name, BatchSize=batch_size, Enabled=True
    )["UUID"]
    ctx.on_cleanup(lambda: _delete_esm(ctx, esm_uuid))
    _wait_for_esm_state(ctx, esm_uuid, "Enabled")
    return esm_uuid


def _delete_esm(ctx, esm_uuid: str) -> None:
    lam = ctx.client("lambda")
    try:
        lam.delete_event_source_mapping(UUID=esm_uuid)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_for_esm_state(ctx, esm_uuid: str, desired_state: str, timeout_s: float = 120.0) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=esm_uuid)["State"]
        if state == desired_state:
            return state
        time.sleep(3)
    raise AssertionError(f"event source mapping never reached {desired_state!r}, last state={state!r}")


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
