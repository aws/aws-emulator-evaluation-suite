"""cfn-deploy-firehose-missing-kinesis-permission-negative."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "cfn-deploy-firehose-missing-kinesis-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["firehose", "kinesis", "s3"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Firehose stream whose role lacks only kinesis:GetRecords delivers nothing to S3
    and logs Kinesis.AccessDenied, while a same-stack sibling with GetRecords on the same Kinesis
    stream delivers, and granting the permission in place restores delivery."""
    template = _build_template()
    stack = _deploy_cfn(ctx, template)
    outputs = stack["outputs"]
    bucket_name = outputs["BucketName"]
    stream_name = outputs["StreamName"]
    log_group = outputs["LogGroupName"]
    bad_log_stream = outputs["BadLogStreamName"]
    bad_role_name = outputs["BadRoleName"]
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

    # Positive control: the fully-permissioned sibling stream, reading the SAME Kinesis
    # stream, delivers normally.
    _poll_until(
        lambda: _find_marker_in_bucket(ctx, bucket_name, "good/", good_marker),
        lambda found: found,
        timeout_s=240.0,
        interval_s=5.0,
        ctx=ctx,
        description=f"good-role marker {good_marker} delivered under good/",
    )

    # Specific error code: Firehose's own CloudWatch delivery-error log names the exact cause.
    error_code = _poll_until(
        lambda: _find_error_code(ctx, log_group, bad_log_stream),
        lambda code: code is not None,
        timeout_s=180.0,
        interval_s=2.0,
        ctx=ctx,
        description=f"Kinesis read error logged for {log_group}/{bad_log_stream}",
    )
    assert error_code == "Kinesis.AccessDenied", f"expected Kinesis.AccessDenied, got {error_code!r}"

    # Effect absent, read after the sibling delivered the same stream and the bad stream logged
    # its failed read: the broken role cannot pull records, so its marker is not in S3.
    deadline = time.monotonic() + 150.0
    while time.monotonic() < deadline:
        found = _find_marker_in_bucket(ctx, bucket_name, "bad/", bad_marker)
        assert found is False, f"bad-role marker {bad_marker} unexpectedly appeared under bad/ before the {150.0}s absence window elapsed"
        time.sleep(10)
    found = _find_marker_in_bucket(ctx, bucket_name, "bad/", bad_marker)
    assert found is False, f"bad-role marker {bad_marker} unexpectedly appeared under bad/ despite the denied read"

    # Restore: grant the SAME role the missing kinesis:GetRecords permission (in place, same
    # role name, same delivery stream -- nothing recreated) and demand the identical pipeline
    # that was withheld above now delivers. This is the beat that separates "this specific
    # permission gap blocks delivery" from "this bad-role stream never delivers for any reason".
    iam = ctx.client("iam")
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamARN"]
    iam.put_role_policy(
        RoleName=bad_role_name,
        PolicyName="FirehoseAccess",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": _kinesis_actions_full(),
                        "Resource": stream_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": _s3_actions_full(),
                        "Resource": [
                            f"arn:aws:s3:::{bucket_name}",
                            f"arn:aws:s3:::{bucket_name}/*",
                        ],
                    },
                    {"Effect": "Allow", "Action": ["logs:PutLogEvents"], "Resource": "*"},
                ],
            }
        ),
    )
    restored_marker = ctx.unique_name("restored-")
    kinesis.put_record(
        StreamName=stream_name,
        Data=json.dumps({"marker": restored_marker}).encode(),
        PartitionKey="pk-restored",
    )
    _poll_until(
        lambda: _find_marker_in_bucket(ctx, bucket_name, "bad/", restored_marker),
        lambda found: found,
        timeout_s=240.0,
        interval_s=2.0,
        ctx=ctx,
        description=f"restored-role marker {restored_marker} delivered under bad/ after granting kinesis:GetRecords on {bad_role_name}",
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None
):
    left = None if ctx is None else ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))
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


def _kinesis_actions_missing_get_records() -> list[str]:
    return [
        "kinesis:DescribeStream",
        "kinesis:DescribeStreamSummary",
        "kinesis:GetShardIterator",
        "kinesis:ListShards",
    ]


def _kinesis_actions_full() -> list[str]:
    return _kinesis_actions_missing_get_records() + ["kinesis:GetRecords"]


def _s3_actions_full() -> list[str]:
    return [
        "s3:AbortMultipartUpload",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:PutObject",
    ]


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
                "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
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
                _kinesis_actions_missing_get_records(),
                _s3_actions_full(),
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
            "BadRoleName": {"Value": {"Ref": "BadRole"}},
        },
    }
    return json.dumps(template)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
