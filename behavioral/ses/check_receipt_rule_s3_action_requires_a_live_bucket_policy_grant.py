"""receipt-rule-s3-action-requires-a-live-bucket-policy-grant."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-s3-action-requires-a-live-bucket-policy-grant"
GROUP = "overly-permissive"
SERVICES = ["ses"]

# SES email receiving exists only in some regions, so the SES client is pinned to a receiving
# region; S3 buckets are exempt from the same-region rule, so the bucket may live anywhere.
# https://docs.aws.amazon.com/general/latest/gr/ses.html#ses_inbound_endpoints
_RECEIVING_REGIONS = ("us-east-1", "us-west-2", "eu-west-1")
_DEFAULT_RECEIVING_REGION = "us-east-1"


def _client_error(fn) -> dict:
    """Return the botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_call(fn, *, timeout_s, interval_s, description):
    """Call fn() until it stops raising ClientError; raise on the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            last = exc.response.get("Error", {})
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not succeed within {timeout_s}s; last refusal {last!r}"
            )
        time.sleep(interval_s)


def _create_bucket(s3, name: str, region: str) -> None:
    """us-east-1 is the one region whose CreateBucket must NOT carry a LocationConstraint."""
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _delete_bucket(s3, name: str) -> None:
    """Empty and delete this check's own bucket."""
    listed = s3.list_objects_v2(Bucket=name)
    for obj in listed.get("Contents") or []:
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _ses_grant_policy(bucket: str, account: str, key_pattern: str = "*") -> str:
    """The bucket policy the SES Developer Guide publishes for the "Deliver to S3 bucket" action.
    https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html"""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSESPuts",
                    "Effect": "Allow",
                    "Principal": {"Service": "ses.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/{key_pattern}",
                    "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
                }
            ],
        }
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An S3Action rule on an existing bucket without an ses.amazonaws.com grant is refused with
    InvalidS3Configuration, distinguishably from a missing bucket, and persists nothing; the
    published AllowSESPuts policy makes the identical call succeed with the action readable back.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    recv_region = (
        ctx.region if ctx.region in _RECEIVING_REGIONS else _DEFAULT_RECEIVING_REGION
    )
    ses = ctx.client("ses", region=recv_region)
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-ses-inbound-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )
    # The bucket must be observably real, so the refusal below is not "no such bucket".
    s3.head_bucket(Bucket=bucket)
    existing_policy = _client_error(lambda: s3.get_bucket_policy(Bucket=bucket))
    assert (existing_policy.get("Code"), existing_policy.get("Message")) == (
        "NoSuchBucketPolicy",
        "The bucket policy does not exist",
    ), (
        f"setup precondition: the fresh bucket must carry NO policy, so the only thing broken in "
        f"the negative leg is the grant; GetBucketPolicy answered {existing_policy!r}"
    )

    rule_set = ctx.unique_name("sim2real-behav-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    # Control: rule creation in this rule set works at all.
    control_rule = "control-add-header"
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={
            "Name": control_rule,
            "Enabled": True,
            "ScanEnabled": False,
            "Actions": [
                {"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": CHECK}}
            ],
        },
    )
    assert control_rule in [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ], "positive control: an AddHeaderAction rule must be creatable in this rule set"

    s3_rule = "s3-delivery"

    def _create_s3_rule(bucket_name: str, prefix: str | None = None):
        action: dict = {"BucketName": bucket_name}
        if prefix is not None:
            action["ObjectKeyPrefix"] = prefix
        return ses.create_receipt_rule(
            RuleSetName=rule_set,
            Rule={
                "Name": s3_rule,
                "Enabled": True,
                "ScanEnabled": False,
                "Actions": [{"S3Action": action}],
            },
        )

    # The bucket is real and owned by this account; only the grant is missing.
    no_grant = _client_error(lambda: _create_s3_rule(bucket))
    assert (no_grant.get("Code"), no_grant.get("Message")) == (
        "InvalidS3Configuration",
        f"Could not write to bucket: {bucket}",
    ), (
        f"an S3Action naming an EXISTING bucket that grants ses.amazonaws.com nothing must be "
        f"refused with InvalidS3Configuration; got {no_grant.get('Code')!r}: "
        f"{no_grant.get('Message')!r}"
    )

    # The two causes must not collapse into one canned answer.
    ghost = ctx.unique_name("sim2real-behav-ses-ghost-bucket-")
    not_found = _client_error(lambda: _create_s3_rule(ghost))
    assert (not_found.get("Code"), not_found.get("Message")) == (
        "InvalidS3Configuration",
        f"No such bucket: {ghost}",
    ), (
        f"a nonexistent bucket must also be InvalidS3Configuration (the incumbent's contract); "
        f"got {not_found.get('Code')!r}: {not_found.get('Message')!r}"
    )
    assert not_found != no_grant, (
        "'the bucket does not exist' and 'the bucket exists but grants SES nothing' are different "
        "faults and must not produce a byte-identical Error dict; both answered "
        f"{no_grant!r}"
    )
    assert bucket not in json.dumps(not_found), (
        f"the refusal for ghost bucket {ghost!r} must not blame the real bucket {bucket!r} — a "
        f"target that echoes a stale subject cannot be used to diagnose either fault; got "
        f"{not_found!r}"
    )

    rules_after_refusals = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ]
    assert s3_rule not in rules_after_refusals, (
        f"a refused CreateReceiptRule must persist nothing; DescribeReceiptRuleSet lists "
        f"{rules_after_refusals!r}"
    )
    assert rules_after_refusals == [control_rule], (
        f"the rule set must hold exactly the positive control after two refusals, got "
        f"{rules_after_refusals!r}"
    )

    s3.put_bucket_policy(Bucket=bucket, Policy=_ses_grant_policy(bucket, account))
    stored = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    principals = [s["Principal"]["Service"] for s in stored["Statement"]]
    assert principals == ["ses.amazonaws.com"], (
        f"the grant must be observably stored before anything is concluded from its effect; "
        f"GetBucketPolicy reported principals {principals!r}"
    )

    # A new bucket policy takes minutes to become effective for SES's pre-flight check.
    _poll_call(
        lambda: _create_s3_rule(bucket),
        timeout_s=300,
        interval_s=10,
        description="CreateReceiptRule accepts the S3Action once ses.amazonaws.com is granted "
        "s3:PutObject on the bucket",
    )

    described = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=s3_rule)["Rule"]
    actions = described["Actions"]
    assert len(actions) == 1, f"expected exactly one action on {s3_rule!r}, got {actions!r}"
    assert actions[0]["S3Action"]["BucketName"] == bucket, (
        f"DescribeReceiptRule must report the granted bucket {bucket!r}, got "
        f"{actions[0]!r}"
    )
    final_rules = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ]
    assert sorted(final_rules) == sorted([control_rule, s3_rule]), (
        f"the rule set must now hold exactly the control and the S3 rule, got {final_rules!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
