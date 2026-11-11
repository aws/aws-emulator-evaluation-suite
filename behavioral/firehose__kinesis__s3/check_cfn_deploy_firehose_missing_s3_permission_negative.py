"""cfn-deploy-firehose-missing-s3-permission-negative."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "cfn-deploy-firehose-missing-s3-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CloudFormation-deployed Firehose stream whose role lacks s3:PutObject delivers nothing to the
    bucket and logs the S3.AccessDenied delivery error, while its sibling stream with s3:PutObject
    delivers the record from the same Kinesis source."""
    template = _build_template()
    stack = _deploy_cfn(ctx, template)
    outputs = stack["outputs"]
    bucket_name = outputs["BucketName"]
    stream_name = outputs["StreamName"]
    log_group = outputs["LogGroupName"]
    bad_log_stream = outputs["BadLogStreamName"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    good_marker = ctx.unique_name("good-")
    bad_marker = ctx.unique_name("bad-")
    kinesis = ctx.client("kinesis")
    kinesis.put_record(
        StreamName=stream_name,
        Data=json.dumps({"marker": good_marker}).encode(),
        PartitionKey="pk-good",
    )
    kinesis.put_record(
        StreamName=stream_name,
        Data=json.dumps({"marker": bad_marker}).encode(),
        PartitionKey="pk-bad",
    )

    # Positive control: the fully-permissioned sibling stream, sourcing the SAME Kinesis
    # stream, delivers normally. Its own latency calibrates how long we hold the absence
    # check below, so a target that is merely slower (but still over-permissive) cannot
    # masquerade as correctly denying delivery.
    good_control_start = time.monotonic()
    _poll_until(
        lambda: _find_marker_in_bucket(ctx, bucket_name, "good/", good_marker),
        lambda found: found,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"good-role marker {good_marker} delivered under good/",
    )
    good_control_latency_s = time.monotonic() - good_control_start

    # Effect absent: hold for at least 3x the positive control's own measured delivery
    # latency (never less than one 60 s buffering cycle), then assert nothing ever landed under
    # the broken role's prefix.
    absence_window_s = max(60.0, 3.0 * good_control_latency_s)
    deadline = time.monotonic() + absence_window_s
    while time.monotonic() < deadline:
        assert _find_marker_in_bucket(ctx, bucket_name, "bad/", bad_marker) is False, (
            f"bad/ prefix must stay empty of {bad_marker!r} for the full "
            f"{absence_window_s:.0f}s absence window (>=3x the {good_control_latency_s:.0f}s "
            "positive-control latency); BadRole lacks s3:PutObject so this delivery must "
            "never succeed"
        )
        time.sleep(2)
    assert _find_marker_in_bucket(ctx, bucket_name, "bad/", bad_marker) is False, (
        f"bad/ prefix must remain empty of {bad_marker!r} after the {absence_window_s:.0f}s "
        "absence window; BadRole lacks s3:PutObject so this delivery must never succeed"
    )

    # Specific error code: Firehose's own CloudWatch delivery-error log names the exact cause.
    error_code = _poll_until(
        lambda: _find_error_code(ctx, log_group, bad_log_stream),
        lambda code: code is not None,
        timeout_s=180.0,
        interval_s=10.0,
        description=f"S3 delivery error logged for {log_group}/{bad_log_stream}",
    )
    assert error_code == "S3.AccessDenied", (
        f"Firehose's CloudWatch delivery-error log for {log_group}/{bad_log_stream} must name "
        f"the exact cause 'S3.AccessDenied' (BadRole lacks s3:PutObject); got {error_code!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _find_marker_in_bucket(ctx, bucket_name: str, prefix: str, marker: str) -> bool:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    for obj in resp.get("Contents", []):
        body = s3.get_object(Bucket=bucket_name, Key=obj["Key"])["Body"].read()
        if marker.encode() in body:
            return True
    return False


def _find_error_code(ctx, log_group: str, log_stream: str) -> str | None:
    logs = ctx.client("logs")
    try:
        resp = logs.get_log_events(
            logGroupName=log_group, logStreamName=log_stream, startFromHead=True
        )
    except ClientError:
        return None
    for event in resp.get("events", []):
        match = re.search(r'"errorCode"\s*:\s*"([^"]+)"', event.get("message", ""))
        if match:
            return match.group(1)
    return None


def _kinesis_actions_full() -> list[str]:
    return [
        "kinesis:DescribeStream",
        "kinesis:DescribeStreamSummary",
        "kinesis:GetShardIterator",
        "kinesis:GetRecords",
        "kinesis:ListShards",
    ]


def _s3_actions_missing_put_object() -> list[str]:
    return [
        "s3:AbortMultipartUpload",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
    ]


def _s3_actions_full() -> list[str]:
    return _s3_actions_missing_put_object() + ["s3:PutObject"]


def _role_resource(
    kinesis_actions: list[str], s3_actions: list[str], log_group_ref: str
) -> dict[str, Any]:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "Policies": [
                {
                    "PolicyName": "FirehoseAccess",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": kinesis_actions,
                                "Resource": {"Fn::GetAtt": ["SourceStream", "Arn"]},
                            },
                            {
                                "Effect": "Allow",
                                "Action": s3_actions,
                                "Resource": [
                                    {"Fn::GetAtt": ["DestBucket", "Arn"]},
                                    {"Fn::Sub": "${DestBucket.Arn}/*"},
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["logs:PutLogEvents"],
                                "Resource": "*",
                            },
                        ],
                    },
                }
            ],
        },
    }


def _delivery_stream_resource(
    role_logical_id: str, prefix: str, log_stream_logical_id: str
) -> dict[str, Any]:
    return {
        "Type": "AWS::KinesisFirehose::DeliveryStream",
        "Properties": {
            "DeliveryStreamType": "KinesisStreamAsSource",
            "KinesisStreamSourceConfiguration": {
                "KinesisStreamARN": {"Fn::GetAtt": ["SourceStream", "Arn"]},
                "RoleARN": {"Fn::GetAtt": [role_logical_id, "Arn"]},
            },
            "S3DestinationConfiguration": {
                "BucketARN": {"Fn::GetAtt": ["DestBucket", "Arn"]},
                "RoleARN": {"Fn::GetAtt": [role_logical_id, "Arn"]},
                "Prefix": prefix,
                "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                "CloudWatchLoggingOptions": {
                    "Enabled": True,
                    "LogGroupName": {"Ref": "LogGroup"},
                    "LogStreamName": {"Ref": log_stream_logical_id},
                },
            },
        },
    }


def _build_template() -> str:
    template: dict[str, Any] = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceStream": {
                "Type": "AWS::Kinesis::Stream",
                "Properties": {"ShardCount": 1},
            },
            "DestBucket": {"Type": "AWS::S3::Bucket"},
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"RetentionInDays": 1},
            },
            "GoodLogStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {"LogGroupName": {"Ref": "LogGroup"}},
            },
            "BadLogStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {"LogGroupName": {"Ref": "LogGroup"}},
            },
            "GoodRole": _role_resource(
                _kinesis_actions_full(), _s3_actions_full(), "LogGroup"
            ),
            "BadRole": _role_resource(
                _kinesis_actions_full(),
                _s3_actions_missing_put_object(),
                "LogGroup",
            ),
            "GoodDeliveryStream": _delivery_stream_resource(
                "GoodRole", "good/", "GoodLogStream"
            ),
            "BadDeliveryStream": _delivery_stream_resource(
                "BadRole", "bad/", "BadLogStream"
            ),
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "DestBucket"}},
            "StreamName": {"Value": {"Ref": "SourceStream"}},
            "LogGroupName": {"Value": {"Ref": "LogGroup"}},
            "BadLogStreamName": {"Value": {"Ref": "BadLogStream"}},
        },
    }
    return json.dumps(template)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
