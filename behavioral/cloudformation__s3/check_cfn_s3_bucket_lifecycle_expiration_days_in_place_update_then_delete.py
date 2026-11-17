"""cfn-s3-bucket-lifecycle-expiration-days-in-place-update-then-delete."""

from __future__ import annotations

import datetime as dt
import json
import re
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-lifecycle-expiration-days-in-place-update-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_RULE_ID = "sim2real-expire-days"
_NOT_FOUND = ("NoSuchBucket", "The specified bucket does not exist")
#: A stack create/update/delete finishes within minutes; the cap only stops a hung wait.
_WAITER_CFG = {"Delay": 5, "MaxAttempts": 180}
#: A freshly-written rule set can take a while before a PutObject is stamped from it.
_EXPIRY_PROPAGATE_S = 600.0


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::S3::Bucket's LifecycleConfiguration deploys, reads back through
    GetBucketLifecycleConfiguration, stamps PutObject's Expiration header from Days, an in-place
    CFN update to Days takes effect on the next write, and the stack delete removes the bucket.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    stack_name = ctx.unique_name("sim2real-cfnreal-lcp-")
    bucket = ctx.unique_name("sim2real-cfnreal-lcp-")

    ctx.on_cleanup(lambda: _teardown(cfn, s3, stack_name))

    # ---- 1. create: declared 5-day expiration, read back through S3's own API --------------
    cfn.create_stack(StackName=stack_name, TemplateBody=_template(bucket, 5))
    _wait(cfn, "stack_create_complete", stack_name)
    physical_before = _physical_bucket_id(cfn, stack_name)
    assert physical_before == bucket, (
        f"the stack must provision the bucket under its own name: {physical_before!r}"
    )
    _assert_rule_days(s3, bucket, 5)
    _assert_put_expiry(ctx, s3, bucket, "first.txt", 5)

    # ---- 2. in-place update: 5 days -> 12 days ----------------------------------------------
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(bucket, 12))
    _wait(cfn, "stack_update_complete", stack_name)
    physical_after = _physical_bucket_id(cfn, stack_name)
    assert physical_after == physical_before, (
        f"a mutable property change must update the SAME bucket, not replace it: "
        f"before {physical_before!r}, after {physical_after!r}"
    )
    _assert_rule_days(s3, bucket, 12)
    _assert_put_expiry(ctx, s3, bucket, "second.txt", 12)

    # ---- 3. DeleteStack: the bucket it owns is gone -----------------------------------------
    _empty_bucket(s3, bucket)
    cfn.delete_stack(StackName=stack_name)
    _wait(cfn, "stack_delete_complete", stack_name)
    _assert_refused_soon(
        ctx,
        lambda: s3.get_bucket_lifecycle_configuration(Bucket=bucket),
        _NOT_FOUND,
        "GetBucketLifecycleConfiguration after DeleteStack",
    )


def _template(bucket: str, days: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": bucket,
                        "LifecycleConfiguration": {
                            "Rules": [
                                {
                                    "Id": _RULE_ID,
                                    "Status": "Enabled",
                                    "Prefix": "",
                                    "ExpirationInDays": days,
                                }
                            ]
                        },
                    },
                },
            },
        }
    )


def _assert_rule_days(s3, bucket: str, days: int) -> None:
    """GetBucketLifecycleConfiguration must reproduce the one rule's id, status and Days."""
    rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    assert len(rules) == 1, f"the templated bucket must carry exactly one rule: {rules!r}"
    rule = rules[0]
    got = (rule.get("ID"), rule.get("Status"), rule.get("Expiration", {}).get("Days"))
    assert got == (_RULE_ID, "Enabled", days), (
        f"the rule must read back as (id, status, days) = {(_RULE_ID, 'Enabled', days)!r}, "
        f"got {got!r}"
    )


def _expected_expiry(last_modified: dt.datetime, days: int) -> dt.datetime:
    """x-amz-expiration's expiry-date: LastModified + Days, rounded up to the next UTC midnight."""
    due = last_modified.astimezone(dt.timezone.utc) + dt.timedelta(days=days)
    midnight = dt.datetime(due.year, due.month, due.day, tzinfo=dt.timezone.utc)
    return midnight + dt.timedelta(days=1)


def _parse_expiration(header: str) -> tuple[dt.datetime, str]:
    """``(expiry_date, rule_id)`` out of an ``expiry-date="...", rule-id="..."`` header.

    The expiry-date value itself carries a comma (its weekday name), so the two fields are
    pulled out by their own quoted spans rather than split on ``,``.
    """
    expiry_match = re.search(r'expiry-date="([^"]*)"', header)
    rule_match = re.search(r'rule-id="([^"]*)"', header)
    assert expiry_match and rule_match, f"malformed Expiration header: {header!r}"
    expiry = dt.datetime.strptime(expiry_match.group(1), "%a, %d %b %Y %H:%M:%S %Z").replace(
        tzinfo=dt.timezone.utc
    )
    return expiry, rule_match.group(1)


def _assert_put_expiry(ctx, s3, bucket: str, key: str, days: int) -> None:
    """PutObject's Expiration header must name the rule and the Days-derived expiry date.

    A just-changed rule set can take a while to be the one new writes are stamped with, so the
    put is retried until its header matches the rule currently on the bucket.
    """
    budget = ctx.time_left()
    cap = _EXPIRY_PROPAGATE_S if budget is None else min(_EXPIRY_PROPAGATE_S, max(1.0, budget - 5.0))
    deadline = time.monotonic() + cap
    parsed = None
    while parsed is None or parsed[1] != _RULE_ID:
        put = s3.put_object(Bucket=bucket, Key=key, Body=b"x")
        header = put.get("Expiration")
        parsed = _parse_expiration(header) if header else None
        if parsed is not None and parsed[1] == _RULE_ID:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"PutObject {key!r} was never stamped by rule {_RULE_ID!r} within {cap:.0f}s; "
                f"last Expiration header {header!r}"
            )
        time.sleep(3.0)
    expiry, rule_id = parsed
    modified = s3.head_object(Bucket=bucket, Key=key)["LastModified"]
    want = _expected_expiry(modified, days)
    assert expiry == want, (
        f"a {days}-day rule on an object last modified {modified.isoformat()} must expire at "
        f"{want.isoformat()}; the header said {expiry.isoformat()}"
    )


def _empty_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait(cfn, waiter_name: str, stack_name: str) -> None:
    """Block on a CloudFormation waiter; a WaiterError names the stack's own failure reason."""
    try:
        cfn.get_waiter(waiter_name).wait(StackName=stack_name, WaiterConfig=_WAITER_CFG)
    except WaiterError as exc:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        raise AssertionError(
            f"{waiter_name} on {stack_name!r} did not reach its terminal state: "
            f"{stack['StackStatus']} ({stack.get('StackStatusReason')!r}); {exc}"
        ) from exc


def _physical_bucket_id(cfn, stack_name: str) -> str:
    detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Bucket")
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def _assert_refused_soon(ctx, fn, want: tuple[str, str], what: str) -> None:
    """A delete's effect reaches every read within seconds; retry until fn() is refused as want."""
    budget = ctx.time_left()
    deadline = time.monotonic() + (60.0 if budget is None else min(60.0, max(1.0, budget - 5.0)))
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} still succeeded past its deadline: {result!r}")
        time.sleep(2.0)


def _teardown(cfn, s3, stack_name: str) -> None:
    """Empty the bucket (if any), delete the stack and wait; a stack already gone is fine."""
    try:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    for res in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]:
        if res["ResourceType"] == "AWS::S3::Bucket":
            _empty_bucket(s3, res["PhysicalResourceId"])
    cfn.delete_stack(StackName=stack_name)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig=_WAITER_CFG
        )
    except WaiterError as exc:
        final = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        raise AssertionError(
            f"teardown of {stack_name!r} ended {final['StackStatus']}: "
            f"{final.get('StackStatusReason')!r}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
