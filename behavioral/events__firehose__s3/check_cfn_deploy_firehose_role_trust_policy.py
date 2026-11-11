"""cfn-deploy-firehose-role-trust-policy."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-firehose-role-trust-policy"
GROUP = "deployment-order"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CloudFormation-deployed IAM role for Firehose ends up with the correct
    firehose.amazonaws.com trust statement (asserted via GetRole, not just the template we
    submitted) AND the role actually lets Firehose deliver a record to S3."""
    bucket_name = _xname(ctx, "bucket").lower()
    stream_name = _xname(ctx, "stream")
    role_name = _xname(ctx, "fhrole")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
                "FirehoseRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
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
            },
            "Outputs": {
                "BucketName": {"Value": {"Ref": "Bucket"}},
                "StreamName": {"Value": {"Ref": "DeliveryStream"}},
                "RoleName": {"Value": {"Ref": "FirehoseRole"}},
            },
        }
    )

    result = _deploy_cfn(ctx, template, timeout_s=300.0)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))
    outputs = result["outputs"]
    assert outputs["RoleName"] == role_name, (
        f"stack output RoleName={outputs.get('RoleName')!r}, expected {role_name!r}"
    )

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    statements = role["AssumeRolePolicyDocument"]["Statement"]
    matching = [
        s
        for s in statements
        if s.get("Effect") == "Allow"
        and s.get("Principal", {}).get("Service") == "firehose.amazonaws.com"
        and s.get("Action") in ("sts:AssumeRole", ["sts:AssumeRole"])
    ]
    assert len(matching) == 1, f"expected exactly one firehose trust statement, got: {statements}"

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
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": (marker + "\n").encode()})

    body = _wait_for_s3_marker(ctx, bucket_name, marker, timeout_s=240.0)
    assert marker in body, f"marker {marker!r} not found in delivered S3 object body: {body!r}"


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

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
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
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
    assert result is not None
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
