"""cfn-deploy-firehose-role-missing-trust-fails-delivery."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-firehose-role-missing-trust-fails-delivery"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An EventBridge rule's event reaches the S3 prefix of a Firehose stream whose role trusts
    firehose.amazonaws.com, and never reaches the prefix of an otherwise identical stream whose role
    trusts only ec2.amazonaws.com, whether or not that second stack deploys."""
    bucket_name = _xname(ctx, "bucket").lower()
    bad_bucket_name = _xname(ctx, "badbucket").lower()
    good_stream = _xname(ctx, "goodstream")
    bad_stream = _xname(ctx, "badstream")
    good_role = _xname(ctx, "goodrole")
    bad_role = _xname(ctx, "badrole")
    events_role = _xname(ctx, "evrole")
    bad_events_role = _xname(ctx, "evrole2")
    rule_name = _xname(ctx, "rule")
    bad_rule_name = _xname(ctx, "rule2")
    source = f"sim2real.negtrust.{rule_name}"
    bad_source = f"sim2real.negtrust.{bad_rule_name}"

    def _s3_policy(bucket_logical: str) -> dict[str, Any]:
        return {
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
                        {"Fn::GetAtt": [bucket_logical, "Arn"]},
                        {"Fn::Sub": f"${{{bucket_logical}.Arn}}/*"},
                    ],
                }
            ],
        }

    def _events_role_props(role_name: str, stream_logical: str) -> dict[str, Any]:
        return {
            "RoleName": role_name,
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
                                "Resource": {"Fn::GetAtt": [stream_logical, "Arn"]},
                            }
                        ],
                    },
                }
            ],
        }

    # Two INDEPENDENT stacks (not one stack with two targets): CloudFormation validates that a
    # KinesisFirehose::DeliveryStream's role can actually be used at creation time, so a stream
    # backed by a role with no firehose.amazonaws.com trust statement fails stack creation
    # (CREATE_FAILED -> rollback) rather than silently creating and never delivering. Putting
    # both streams in ONE stack would mean the bad stream's failure rolls back the good stream
    # too, making it impossible to observe the good stream's successful delivery. Splitting them
    # lets each stack's fate speak for itself: the good stack must reach CREATE_COMPLETE and
    # deliver; the bad stack's broken trust must prevent delivery, whether that surfaces as a
    # failed deploy (proving the trust check blocks it before anything can run) or -- if it were
    # to somehow reach CREATE_COMPLETE -- as a stream that never delivers.
    good_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
                "GoodRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": good_role,
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
                        "Policies": [{"PolicyName": "s3-access", "PolicyDocument": _s3_policy("Bucket")}],
                    },
                },
                "GoodStream": {
                    "Type": "AWS::KinesisFirehose::DeliveryStream",
                    "DependsOn": "GoodRole",
                    "Properties": {
                        "DeliveryStreamName": good_stream,
                        "DeliveryStreamType": "DirectPut",
                        "ExtendedS3DestinationConfiguration": {
                            "BucketARN": {"Fn::GetAtt": ["Bucket", "Arn"]},
                            "RoleARN": {"Fn::GetAtt": ["GoodRole", "Arn"]},
                            "Prefix": "good/",
                            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                        },
                    },
                },
                "EventsRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": _events_role_props(events_role, "GoodStream"),
                },
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": rule_name,
                        "State": "ENABLED",
                        "EventPattern": {"source": [source]},
                        "Targets": [
                            {
                                "Id": "good-target",
                                "Arn": {"Fn::GetAtt": ["GoodStream", "Arn"]},
                                "RoleArn": {"Fn::GetAtt": ["EventsRole", "Arn"]},
                            }
                        ],
                    },
                },
            },
        }
    )

    bad_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "BadBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": bad_bucket_name},
                },
                "BadRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": bad_role,
                        # The ONE broken thing: this role does NOT trust firehose.amazonaws.com.
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {"PolicyName": "s3-access", "PolicyDocument": _s3_policy("BadBucket")}
                        ],
                    },
                },
                "BadStream": {
                    "Type": "AWS::KinesisFirehose::DeliveryStream",
                    "DependsOn": "BadRole",
                    "Properties": {
                        "DeliveryStreamName": bad_stream,
                        "DeliveryStreamType": "DirectPut",
                        "ExtendedS3DestinationConfiguration": {
                            "BucketARN": {"Fn::GetAtt": ["BadBucket", "Arn"]},
                            "RoleARN": {"Fn::GetAtt": ["BadRole", "Arn"]},
                            "Prefix": "bad/",
                            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
                        },
                    },
                },
                "BadEventsRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": _events_role_props(bad_events_role, "BadStream"),
                },
                "BadRule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": bad_rule_name,
                        "State": "ENABLED",
                        "EventPattern": {"source": [bad_source]},
                        "Targets": [
                            {
                                "Id": "bad-target",
                                "Arn": {"Fn::GetAtt": ["BadStream", "Arn"]},
                                "RoleArn": {"Fn::GetAtt": ["BadEventsRole", "Arn"]},
                            }
                        ],
                    },
                },
            },
        }
    )

    # Positive control: the properly-trusted stack must deploy AND deliver.
    _deploy_cfn(ctx, good_template, timeout_s=420.0)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    firehose = ctx.client("firehose")
    _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=good_stream)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=3.0,
        description=f"delivery stream {good_stream} ACTIVE",
    )

    marker = ctx.unique_name("sim2real-marker-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real.negtrust.test",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )
    good_body = _wait_for_marker_under_prefix(ctx, bucket_name, "good/", marker, timeout_s=240.0)
    assert marker in good_body

    # Negative: deploy the mistrusted stack WITHOUT letting a failed deploy raise -- either
    # outcome (deploy fails, or deploy succeeds but never delivers) proves the missing trust
    # statement is the reason delivery cannot happen.
    bad_name, bad_status = _deploy_cfn_tolerant(ctx, bad_template, timeout_s=300.0)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bad_bucket_name))

    if bad_status != "CREATE_COMPLETE":
        assert bad_status in {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, (
            f"unexpected stack status {bad_status!r} for bad-trust stack {bad_name}"
        )
        return

    # Deploy unexpectedly succeeded (e.g. an emulator that doesn't validate trust at create
    # time) -- fall through to proving the stream still never delivers.
    bad_marker = ctx.unique_name("sim2real-marker-")
    events.put_events(
        Entries=[
            {
                "Source": bad_source,
                "DetailType": "sim2real.negtrust.test",
                "Detail": json.dumps({"marker": bad_marker}),
            }
        ]
    )
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        assert _find_marker_under_prefix(ctx, bad_bucket_name, "bad/", bad_marker) is None, (
            "record was delivered to the bad-trust stream's bucket despite its Firehose role's "
            "trust policy not allowing firehose.amazonaws.com to assume it"
        )
        time.sleep(2)
    assert _find_marker_under_prefix(ctx, bad_bucket_name, "bad/", bad_marker) is None


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


def _deploy_cfn_tolerant(ctx, template, *, timeout_s: float = 300.0) -> tuple[str, str]:
    """Like _deploy_cfn but returns the terminal status instead of raising on failure, so the
    caller can treat CREATE_FAILED/ROLLBACK_COMPLETE as a valid (expected) negative outcome."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    del stack_id
    return name, status


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


def _find_marker_under_prefix(ctx, bucket: str, prefix: str, marker: str) -> str | None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode("utf-8", "replace")
            if marker in body:
                return body
    return None


def _wait_for_marker_under_prefix(
    ctx, bucket: str, prefix: str, marker: str, timeout_s: float = 240.0, interval_s: float = 10.0
) -> str:
    result = _poll_until(
        lambda: _find_marker_under_prefix(ctx, bucket, prefix, marker),
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"marker delivered to s3://{bucket}/{prefix}",
    )
    assert result is not None
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
