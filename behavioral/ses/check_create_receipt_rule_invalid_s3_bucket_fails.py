"""create-receipt-rule-invalid-s3-bucket-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-receipt-rule-invalid-s3-bucket-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _client_error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _require_receipt_region(ctx):
    """SES email receiving (receipt rules) is region-limited; skip elsewhere."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


def _track_receipt_rule_set(ctx, ses, name):
    """Register teardown for a receipt rule set: deactivate the active set first (an active
    rule set cannot be deleted), then delete this one."""
    def _teardown():
        active_set = (ses.describe_active_receipt_rule_set().get("Metadata") or {}).get("Name")
        if active_set == name:  # never deactivate a set this check did not create
            ses.set_active_receipt_rule_set()
        ses.delete_receipt_rule_set(RuleSetName=name)

    ctx.on_cleanup(_teardown)
    return name


def _ses_write_policy(bucket, account):
    """The policy Amazon SES requires on a bucket before it will accept an S3Action naming it:
    https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html"""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowSESPuts",
            "Effect": "Allow",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"aws:Referer": account}},
        }],
    })


def _empty_and_delete_bucket(s3, bucket):
    """SES puts a permission-check object into an S3Action's bucket as soon as the rule that
    names it is created, so a plain delete_bucket leaves it BucketNotEmpty."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                   for o in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _make_working_bucket(ctx, s3, account, bucket):
    """Create a bucket and grant SES write access to it, so it is a real, usable S3Action
    destination rather than merely an existing bucket."""
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=_ses_write_policy(bucket, account))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """CreateReceiptRule with an S3Action naming a missing bucket fails with InvalidS3Configuration;
    a rule naming a real SES-writable bucket succeeds, as does the same call once the bucket exists.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html"""
    ses = ctx.client("ses")
    s3 = ctx.client("s3")
    _require_receipt_region(ctx)
    account = ctx.client("sts").get_caller_identity()["Account"]

    set_name = ctx.unique_name("sim2real-behav-ruleset-s3-")
    ses.create_receipt_rule_set(RuleSetName=set_name)
    _track_receipt_rule_set(ctx, ses, set_name)

    # Positive control: a rule naming a real, SES-writable bucket must succeed. Without this,
    # "rejects a non-existent bucket" is indistinguishable from "rejects every S3Action".
    control_bucket = ctx.unique_name("sim2real-behav-good-bucket-")
    _make_working_bucket(ctx, s3, account, control_bucket)
    control_rule = "s3-rule-control"
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={
            "Name": control_rule,
            "Enabled": True,
            "Actions": [{"S3Action": {"BucketName": control_bucket}}],
        },
    )
    rules = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"]]
    assert control_rule in rules, f"positive-control S3Action rule was not persisted: {rules}"

    # Break: the same shape of rule, naming a bucket that does not exist yet.
    rule_name = "s3-rule"
    ghost_bucket = ctx.unique_name("sim2real-behav-ghost-bucket-")
    rule_def = {
        "Name": rule_name,
        "Enabled": True,
        "Actions": [{"S3Action": {"BucketName": ghost_bucket}}],
    }
    code = _client_error_code(
        lambda: ses.create_receipt_rule(RuleSetName=set_name, Rule=rule_def)
    )
    assert code == ("InvalidS3Configuration", f"No such bucket: {ghost_bucket}"), (
        f"expected InvalidS3Configuration for a non-existent S3 bucket, got {code!r}"
    )

    # The rejected rule must not be persisted.
    rules = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"]]
    assert rule_name not in rules, f"a rejected receipt rule was persisted: {rules}"

    # Restore: create and configure the exact bucket that was missing, then retry the identical
    # call — it must now succeed, proving the rejection tracked the bucket's absence and nothing
    # else.
    _make_working_bucket(ctx, s3, account, ghost_bucket)
    ses.create_receipt_rule(RuleSetName=set_name, Rule=rule_def)
    rules = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"]]
    assert rule_name in rules, (
        f"identical CreateReceiptRule call still rejected after the bucket was created: {rules}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
