"""deploy-s3express-directorybucket-bucketpolicy-accesspoint-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3express-directorybucket-bucketpolicy-accesspoint-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "s3", "s3control"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

# One documented S3 Express One Zone Availability Zone ID per region.
_EXPRESS_ZONE = {
    "us-east-1": "use1-az4", "us-east-2": "use2-az1", "us-west-2": "usw2-az1",
    "ap-northeast-1": "apne1-az4", "ap-south-1": "aps1-az1", "eu-west-1": "euw1-az1",
    "eu-north-1": "eun1-az1",
}
_VPC_CIDR = "10.71.0.0/16"


def _policy(principal, bucket_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": principal},
                       "Action": "s3express:*", "Resource": bucket_arn}],
    }


def _template(bucket_name, ap_name, zone_id, with_children=True):
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Bucket": {"Type": "AWS::S3Express::DirectoryBucket", "Properties": {
            "BucketName": bucket_name,
            "LocationName": zone_id,
            "DataRedundancy": "SingleAvailabilityZone",
        }},
    }
    outputs = {
        "VpcId": {"Value": {"Ref": "Vpc"}},
        "BucketRef": {"Value": {"Ref": "Bucket"}},
        "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
        "BucketAz": {"Value": {"Fn::GetAtt": ["Bucket", "AvailabilityZoneName"]}},
    }
    if with_children:
        resources["BucketPolicy"] = {"Type": "AWS::S3Express::BucketPolicy", "Properties": {
            "Bucket": {"Ref": "Bucket"},
            "PolicyDocument": _policy(
                {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"},
                {"Fn::GetAtt": ["Bucket", "Arn"]},
            ),
        }}
        # VPC-origin only: the access point is never reachable from the internet.
        resources["AccessPoint"] = {"Type": "AWS::S3Express::AccessPoint", "Properties": {
            "Bucket": {"Ref": "Bucket"},
            "Name": ap_name,
            "VpcConfiguration": {"VpcId": {"Ref": "Vpc"}},
        }}
        outputs["APRef"] = {"Value": {"Ref": "AccessPoint"}}
        outputs["APArn"] = {"Value": {"Fn::GetAtt": ["AccessPoint", "Arn"]}}
        outputs["APNetworkOrigin"] = {"Value": {"Fn::GetAtt": ["AccessPoint", "NetworkOrigin"]}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation S3 Express directory bucket, bucket policy and access point read back.

    An update dropping the policy and access point removes both from the still-present bucket,
    and deleting the stack removes the bucket.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    s3control = ctx.client("s3control")
    zone_id = _EXPRESS_ZONE.get(ctx.region)
    assert zone_id, f"no documented S3 Express One Zone Availability Zone in {ctx.region}"
    stack = ctx.unique_name("sim2real-s3x-cfn-")
    bucket = ctx.unique_name("sim2real-s3x-b-") + f"--{zone_id}--x-s3"
    ap_name = ctx.unique_name("sim2real-s3x-ap-") + f"--{zone_id}--xa-s3"

    stack_id = create_stack(ctx, cf, stack, _template(bucket, ap_name, zone_id))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    bucket_arn = f"arn:{partition}:s3express:{ctx.region}:{ctx.account}:bucket/{bucket}"
    ap_arn = f"arn:{partition}:s3express:{ctx.region}:{ctx.account}:accesspoint/{ap_name}"

    # Ref and GetAtt Arn against an independent ListDirectoryBuckets, never a read by the Ref.
    listed = [(b["Name"], b["BucketArn"]) for b in
              paginate(s3, "list_directory_buckets", "Buckets") if b["Name"] == bucket]
    assert listed == [(out["BucketRef"], out["BucketArn"])] == [(bucket, bucket_arn)], (
        f"ListDirectoryBuckets {listed!r}, Ref {out['BucketRef']!r}, Arn {out['BucketArn']!r}"
    )
    head = s3.head_bucket(Bucket=bucket)
    got_loc = (head["BucketLocationType"], head["BucketLocationName"])
    assert got_loc == ("AvailabilityZone", zone_id), f"HeadBucket location {got_loc!r}"
    zone = ec2.describe_availability_zones(ZoneIds=[zone_id])["AvailabilityZones"][0]
    assert out["BucketAz"] == zone["ZoneName"], (
        f"GetAtt AvailabilityZoneName {out['BucketAz']!r}, EC2 ZoneName {zone['ZoneName']!r}"
    )
    policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    want_policy = _policy(f"arn:{partition}:iam::{ctx.account}:root", bucket_arn)
    assert policy == want_policy, f"bucket policy {policy!r}, expected {want_policy!r}"

    # Access point Ref against the bucket's own listing; every templated property read back.
    def own_access_points():
        return paginate(s3control, "list_access_points_for_directory_buckets", "AccessPointList",
                        AccountId=ctx.account, DirectoryBucket=bucket)

    aps = [(a["Name"], a["AccessPointArn"]) for a in own_access_points()]
    assert aps == [(out["APRef"], out["APArn"])] == [(ap_name, ap_arn)], (
        f"access points {aps!r}, Ref {out['APRef']!r}, Arn {out['APArn']!r}"
    )
    ap = s3control.get_access_point(AccountId=ctx.account, Name=ap_name)
    got_ap = (ap["Bucket"], ap["NetworkOrigin"], ap.get("VpcConfiguration"), out["APNetworkOrigin"])
    assert got_ap == (bucket, "VPC", {"VpcId": out["VpcId"]}, "VPC"), f"access point {got_ap!r}"

    # Children first: the update drops the policy and access point; the bucket still answers.
    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(bucket, ap_name, zone_id, with_children=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    assert own_access_points() == [], f"the dropped access point is listed: {own_access_points()!r}"
    not_found = ("NoSuchAccessPoint", "The specified accesspoint does not exist")
    expect_error(
        lambda: s3control.get_access_point(AccountId=ctx.account, Name=ap_name),
        *not_found,
    )
    not_found_2 = ("NoSuchBucketPolicy", "The bucket policy does not exist")
    expect_error(lambda: s3.get_bucket_policy(Bucket=bucket), *not_found_2)
    assert s3.head_bucket(Bucket=bucket)["BucketArn"] == bucket_arn, "the bucket no longer answers"

    delete_stack(cf, stack_id)
    until_raises(lambda: s3.head_bucket(Bucket=bucket))
    not_found_3 = ("NoSuchBucket", "The specified bucket does not exist")
    expect_error(lambda: s3.get_bucket_policy(Bucket=bucket), *not_found_3)
    gone = [b for b in paginate(s3, "list_directory_buckets", "Buckets") if b["Name"] == bucket]
    assert gone == [], f"the deleted bucket is still listed: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
