"""cfn-stack-update-firehose-s3-prefix-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-update-firehose-s3-prefix-positive"
GROUP = "deployment-order"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Updating the deployed stack's Firehose S3 Prefix parameter changes the key structure of
    subsequently delivered objects: records sent before the update land under the old prefix,
    records sent after the update land under the new prefix."""
    template = _build_template()
    stack = _deploy_cfn(ctx, template, parameters={"S3Prefix": "before/"})
    outputs = stack["outputs"]
    stack_name = stack["stack_name"]
    bucket_name = outputs["BucketName"]
    stream_name = outputs["StreamName"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    marker_before = ctx.unique_name("before-")
    ctx.client("kinesis").put_record(
        StreamName=stream_name,
        Data=json.dumps({"marker": marker_before}).encode(),
        PartitionKey="pk-1",
    )
    _poll_until(
        lambda: _find_marker_in_bucket(ctx, bucket_name, "before/", marker_before),
        lambda found: found,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"marker {marker_before} delivered under before/",
    )

    _update_stack(ctx, stack_name, template, parameters={"S3Prefix": "after/"})

    marker_after = ctx.unique_name("after-")
    ctx.client("kinesis").put_record(
        StreamName=stream_name,
        Data=json.dumps({"marker": marker_after}).encode(),
        PartitionKey="pk-1",
    )
    found_after = _poll_until(
        lambda: _find_marker_in_bucket(ctx, bucket_name, "after/", marker_after),
        lambda found: found,
        timeout_s=240.0,
        interval_s=5.0,
        description=f"marker {marker_after} delivered under after/ post-update",
    )
    assert found_after is True, (
        f"expected marker {marker_after} to be delivered under after/ post-update; "
        f"got found_after={found_after!r}"
    )
    # The post-update record must NOT have landed under the OLD prefix — the key structure
    # genuinely changed, rather than the update being a no-op that happened to also write here.
    found_under_old_prefix = _find_marker_in_bucket(ctx, bucket_name, "before/", marker_after)
    assert found_under_old_prefix is False, (
        f"expected marker {marker_after} to be ABSENT under before/ after the S3Prefix update, "
        f"but found it there — the stack update did not change delivery key structure"
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


def _update_stack(
    ctx, stack_name: str, template, *, parameters=None, timeout_s=300.0
) -> dict[str, Any]:
    """update_stack + poll to a terminal status; asserts UPDATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    cfn.update_stack(**kwargs)
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
        },
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack update {stack_name}",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update {stack_name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"outputs": outputs}


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


def _kinesis_actions_full() -> list[str]:
    return [
        "kinesis:DescribeStream",
        "kinesis:DescribeStreamSummary",
        "kinesis:GetShardIterator",
        "kinesis:GetRecords",
        "kinesis:ListShards",
    ]


def _s3_actions_full() -> list[str]:
    return [
        "s3:AbortMultipartUpload",
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:PutObject",
    ]


def _build_template() -> str:
    template: dict[str, Any] = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "S3Prefix": {"Type": "String", "Default": "before/"}
        },
        "Resources": {
            "SourceStream": {
                "Type": "AWS::Kinesis::Stream",
                "Properties": {"ShardCount": 1},
            },
            "DestBucket": {
                "Type": "AWS::S3::Bucket",
            },
            "FirehoseRole": {
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
                                        "Action": _kinesis_actions_full(),
                                        "Resource": {
                                            "Fn::GetAtt": ["SourceStream", "Arn"]
                                        },
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": _s3_actions_full(),
                                        "Resource": [
                                            {"Fn::GetAtt": ["DestBucket", "Arn"]},
                                            {"Fn::Sub": "${DestBucket.Arn}/*"},
                                        ],
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "DeliveryStream": {
                "Type": "AWS::KinesisFirehose::DeliveryStream",
                "Properties": {
                    "DeliveryStreamType": "KinesisStreamAsSource",
                    "KinesisStreamSourceConfiguration": {
                        "KinesisStreamARN": {
                            "Fn::GetAtt": ["SourceStream", "Arn"]
                        },
                        "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                    },
                    "S3DestinationConfiguration": {
                        "BucketARN": {"Fn::GetAtt": ["DestBucket", "Arn"]},
                        "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                        "Prefix": {"Ref": "S3Prefix"},
                        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                    },
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "DestBucket"}},
            "StreamName": {"Value": {"Ref": "SourceStream"}},
            "DeliveryStreamName": {"Value": {"Ref": "DeliveryStream"}},
        },
    }
    return json.dumps(template)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
