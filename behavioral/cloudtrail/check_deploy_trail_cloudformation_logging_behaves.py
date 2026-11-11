"""deploy-trail-cloudformation-logging-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-trail-cloudformation-logging-behaves"
GROUP = "deploy"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::CloudTrail::Trail actually starts logging
    (GetTrailStatus.IsLogging=true, and the configured EventSelectors are live)
    rather than merely reaching CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    ct = ctx.client("cloudtrail")
    ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-ct-cfn-b-").lower()[:63]
    trail_name = ctx.unique_name("sim2real-ct-cfn-t-")
    stack_name = ctx.unique_name("sim2real-ct-cfn-stack-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "BucketName": {"Type": "String"},
            "TrailName": {"Type": "String"},
        },
        "Resources": {
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": {"Ref": "BucketName"}},
            },
            "TrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "TrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${TrailBucket}"},
                                "Condition": {
                                    "StringEquals": {
                                        "aws:SourceArn": {
                                            "Fn::Sub": "arn:aws:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${TrailName}"
                                        }
                                    }
                                },
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {
                                    "Fn::Sub": "arn:aws:s3:::${TrailBucket}/AWSLogs/${AWS::AccountId}/*"
                                },
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control",
                                        "aws:SourceArn": {
                                            "Fn::Sub": "arn:aws:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${TrailName}"
                                        },
                                    }
                                },
                            },
                        ],
                    },
                },
            },
            "Trail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": "TrailBucketPolicy",
                "Properties": {
                    "TrailName": {"Ref": "TrailName"},
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IncludeGlobalServiceEvents": True,
                    "IsMultiRegionTrail": False,
                    "EventSelectors": [
                        {"ReadWriteType": "All", "IncludeManagementEvents": True}
                    ],
                },
            },
        },
    }

    def _cleanup() -> None:
        try:
            _empty_bucket(ctx, bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 420})
        remaining = ct.describe_trails(trailNameList=[trail_name])["trailList"]
        assert remaining == [], (
            f"expected trail {trail_name!r} gone after stack teardown, found {remaining!r}"
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "BucketName", "ParameterValue": bucket_name},
            {"ParameterKey": "TrailName", "ParameterValue": trail_name},
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    # Confirm the trail is a real, describable resource -- not just a CFN record.
    trails = ct.describe_trails(trailNameList=[trail_name])["trailList"]
    assert len(trails) == 1, f"expected exactly 1 trail named {trail_name!r}, found {trails!r}"
    assert trails[0]["S3BucketName"] == bucket_name, (
        f"expected trail's S3BucketName to be {bucket_name!r}, got {trails[0]['S3BucketName']!r}"
    )

    # The deep signal: logging must actually be ON, not merely CREATE_COMPLETE.
    is_logging = _poll_until(
        lambda: ct.get_trail_status(Name=trail_name)["IsLogging"],
        lambda logging: logging is True,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert is_logging is True, f"expected IsLogging=True on {trail_name!r}, got {is_logging!r}"

    # The event selectors configured through CFN must have actually been applied
    # via PutEventSelectors under the hood.
    selectors = ct.get_event_selectors(TrailName=trail_name)["EventSelectors"]
    assert len(selectors) == 1, f"expected exactly 1 event selector, found {selectors!r}"
    assert selectors[0]["ReadWriteType"] == "All", (
        f"expected ReadWriteType='All', got {selectors[0]['ReadWriteType']!r}"
    )
    assert selectors[0]["IncludeManagementEvents"] is True, (
        f"expected IncludeManagementEvents=True, got {selectors[0]['IncludeManagementEvents']!r}"
    )


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    if predicate(value):
        return value
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last={value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
