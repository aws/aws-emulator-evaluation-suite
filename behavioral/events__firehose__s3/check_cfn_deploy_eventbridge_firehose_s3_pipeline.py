"""cfn-deploy-eventbridge-firehose-s3-pipeline."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-firehose-s3-pipeline"
GROUP = "deployment-order"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CloudFormation stack wires an EventBridge rule -> Firehose delivery stream -> S3
    bucket; a PutEvents call that matches the rule's pattern must be observably delivered as
    an object in the destination bucket (not merely CREATE_COMPLETE on every resource)."""
    bucket_name = _xname(ctx, "bucket").lower()
    stream_name = _xname(ctx, "stream")
    fh_role_name = _xname(ctx, "fhrole")
    ev_role_name = _xname(ctx, "evrole")
    rule_name = _xname(ctx, "rule")
    source = f"sim2real.pipeline.{stream_name}"

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
                "FirehoseRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": fh_role_name,
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
                                "PolicyName": "s3-access",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:PutObject",
                                                "s3:GetBucketLocation",
                                                "s3:ListBucket",
                                                "s3:ListBucketMultipartUploads",
                                                "s3:AbortMultipartUpload",
                                                "s3:GetObject",
                                            ],
                                            "Resource": [
                                                {"Fn::GetAtt": ["Bucket", "Arn"]},
                                                {"Fn::Sub": "${Bucket.Arn}/*"},
                                            ],
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "DeliveryStream": {
                    "Type": "AWS::KinesisFirehose::DeliveryStream",
                    "DependsOn": "FirehoseRole",
                    "Properties": {
                        "DeliveryStreamName": stream_name,
                        "DeliveryStreamType": "DirectPut",
                        "ExtendedS3DestinationConfiguration": {
                            "BucketARN": {"Fn::GetAtt": ["Bucket", "Arn"]},
                            "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                        },
                    },
                },
                "EventsRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": ev_role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "firehose-put",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                                            "Resource": {"Fn::GetAtt": ["DeliveryStream", "Arn"]},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": rule_name,
                        "State": "ENABLED",
                        "EventPattern": {"source": [source]},
                        "Targets": [
                            {
                                "Id": "firehose-target",
                                "Arn": {"Fn::GetAtt": ["DeliveryStream", "Arn"]},
                                "RoleArn": {"Fn::GetAtt": ["EventsRole", "Arn"]},
                            }
                        ],
                    },
                },
            },
            "Outputs": {
                "BucketName": {"Value": {"Ref": "Bucket"}},
                "StreamName": {"Value": {"Ref": "DeliveryStream"}},
                "RuleName": {"Value": {"Ref": "Rule"}},
            },
        }
    )

    result = _deploy_cfn(ctx, template, timeout_s=420.0)
    stack_name = result["stack_name"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))
    outputs = result["outputs"]
    assert outputs["BucketName"] == bucket_name, (
        f"expected stack output BucketName={bucket_name!r}, got {outputs.get('BucketName')!r}"
    )
    assert outputs["StreamName"] == stream_name, (
        f"expected stack output StreamName={stream_name!r}, got {outputs.get('StreamName')!r}"
    )

    firehose = ctx.client("firehose")
    _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=3.0,
        description="delivery stream ACTIVE",
    )

    marker = ctx.unique_name("sim2real-marker-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real.pipeline.test",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    body = _wait_for_s3_marker(ctx, bucket_name, marker, timeout_s=240.0)
    assert marker in body, f"expected marker {marker!r} in delivered S3 object body, got {body!r}"

    # Deploy artifacts must prove teardown, not just delivery: delete the stack in-body (the
    # bucket must be emptied first, since a non-empty bucket makes stack deletion fail) and
    # confirm with an independent read that it is actually gone.
    _empty_bucket(ctx, bucket_name)
    _delete_stack_and_wait(ctx, stack_name)
    cfn = ctx.client("cloudformation")
    try:
        cfn.describe_stacks(StackName=stack_name)
        raise AssertionError(f"expected stack {stack_name} to be gone after delete, but describe_stacks still found it")
    except ClientError as e:
        err = e.response["Error"]
        assert err["Code"] == "ValidationError", (
            f"expected ValidationError for deleted stack {stack_name}, got {err!r}"
        )
        assert err["Message"] == f"Stack with id {stack_name} does not exist", (
            f"expected the deleted stack {stack_name} to be reported missing, got {err!r}"
        )


# ===== helpers =====

_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")):
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
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise AssertionError(f"DeleteObjects left {len(failed)} object(s) in {bucket_name}: {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _find_marker_in_bucket(ctx, bucket: str, marker: str) -> str | None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8", "replace")
            if marker in body:
                return body
    return None


def _wait_for_s3_marker(ctx, bucket: str, marker: str, timeout_s: float = 240.0, interval_s: float = 10.0) -> str:
    result = _poll_until(
        lambda: _find_marker_in_bucket(ctx, bucket, marker),
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"marker delivered to s3://{bucket}",
    )
    assert result is not None, f"marker {marker!r} not found in any object under s3://{bucket}"
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
