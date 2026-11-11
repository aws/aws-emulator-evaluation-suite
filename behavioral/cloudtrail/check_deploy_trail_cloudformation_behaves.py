"""deploy-trail-cloudformation-behaves."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-trail-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A Trail deployed via CloudFormation can actually StartLogging and reach IsLogging=True.

    CREATE_COMPLETE alone proves the control plane accepted the template; it says
    nothing about whether the resulting Trail is a functioning logging pipeline.
    """
    cfn = ctx.client("cloudformation")
    ct = ctx.client("cloudtrail")
    ctx.client("s3")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    trail_name = ctx.unique_name("sim2real-cfn-trail-")
    bucket_name = ctx.unique_name("sim2real-cfn-trailbkt-").lower()
    stack_name = ctx.unique_name("sim2real-cfn-trailstack-")
    trail_arn = f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceArn": trail_arn,
                    }
                },
            },
        ],
    }

    template = {
        "Resources": {
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": bucket_name},
            },
            "TrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "TrailBucket"},
                    "PolicyDocument": bucket_policy,
                },
            },
            "Trail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": "TrailBucketPolicy",
                "Properties": {
                    "TrailName": trail_name,
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": False,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": True,
                },
            },
        }
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name, bucket_name, trail_name, ct, account_id))
    _wait_for_stack(ctx, stack_name, "CREATE_COMPLETE", ("CREATE_FAILED", "ROLLBACK_COMPLETE"))

    # The Trail resource must exist and be describable via the control-plane API.
    trail = ct.get_trail(Name=trail_name)["Trail"]
    assert trail["Name"] == trail_name, f"expected trail name {trail_name!r}, got {trail['Name']!r}"

    status_before = ct.get_trail_status(Name=trail_name)
    assert status_before["IsLogging"] is False, (
        f"expected a freshly-deployed trail to have IsLogging=False, got {status_before['IsLogging']!r}"
    )

    ct.start_logging(Name=trail_name)
    ctx.on_cleanup(lambda: ct.stop_logging(Name=trail_name))

    is_logging = _poll_until(
        lambda: ct.get_trail_status(Name=trail_name)["IsLogging"],
        lambda logging: logging is True,
        timeout_s=60,
        interval_s=3,
    )
    assert is_logging is True, f"expected IsLogging=True within 60s of StartLogging, last saw {is_logging!r}"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last value: {value!r}")


def _wait_for_stack(ctx, stack_name, ok_status, bad_statuses, timeout_s=300.0):
    cfn = ctx.client("cloudformation")

    def _status():
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]

    status = _poll_until(
        _status,
        lambda s: s == ok_status or s in bad_statuses,
        timeout_s=timeout_s,
        interval_s=5,
    )
    if status != ok_status:
        raise AssertionError(f"stack {stack_name} ended in {status}, expected {ok_status}")


def _delete_stack_and_wait(ctx, stack_name, bucket_name, trail_name, ct, account_id):
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    try:
        resp = s3.list_object_versions(Bucket=bucket_name)
        objects = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("Versions", [])]
        objects += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("DeleteMarkers", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 300
    reached_delete_complete = False
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                reached_delete_complete = True
                break
            raise
        if status == "DELETE_COMPLETE":
            reached_delete_complete = True
            break
        time.sleep(5)
    if not reached_delete_complete:
        raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE")

    # The delete is a free negative assertion: the trail this stack created must now be
    # independently unreadable, not merely absent from the stack's own record.
    try:
        ct.get_trail(Name=trail_name)
    except ct.exceptions.TrailNotFoundException as exc:
        message = exc.response["Error"].get("Message", "")
        assert message == f"Unknown trail: {trail_name} for the user: {account_id}", message
    else:
        raise AssertionError(f"trail {trail_name} still describable after stack deletion")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
