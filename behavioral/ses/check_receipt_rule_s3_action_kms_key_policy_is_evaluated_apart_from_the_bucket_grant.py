"""receipt-rule-s3-action-kms-key-policy-is-evaluated-apart-from-the-bucket-grant."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-s3-action-kms-key-policy-is-evaluated-apart-from-the-bucket-grant"
GROUP = "overly-permissive"
SERVICES = ["ses"]

# SES email receiving exists only in some regions, and the KMS key must share the SES endpoint's
# region, so both clients are pinned to a receiving region.
# https://docs.aws.amazon.com/general/latest/gr/ses.html#ses_inbound_endpoints
_RECEIVING_REGIONS = ("us-east-1", "us-west-2", "eu-west-1")
_DEFAULT_RECEIVING_REGION = "us-east-1"


def _client_error(fn) -> dict:
    """Return the botocore Error dict; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_call(fn, *, timeout_s, interval_s, description):
    """Call fn() until it stops raising ClientError; RAISE on the deadline."""
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
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _delete_bucket(s3, name: str) -> None:
    """Empty and delete this check's own bucket."""
    for obj in s3.list_objects_v2(Bucket=name).get("Contents") or []:
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _root_only_key_policy(account: str) -> str:
    """The account-root-only key policy: no service principal is granted anything, so SES has no
    path to the key. This is the deliberate single fault."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "sim2real-root-only",
            "Statement": [
                {
                    "Sid": "EnableIAMUserPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                }
            ],
        }
    )


def _key_policy_with_ses(account: str) -> str:
    """The root-only policy plus the SES encrypt grant."""
    document = json.loads(_root_only_key_policy(account))
    document["Statement"].append(
        {
            "Sid": "AllowSESToEncrypt",
            "Effect": "Allow",
            "Principal": {"Service": "ses.amazonaws.com"},
            "Action": ["kms:Encrypt", "kms:GenerateDataKey*", "kms:Decrypt"],
            "Resource": "*",
            "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
        }
    )
    return json.dumps(document)


def _ses_bucket_policy(bucket: str, account: str) -> str:
    """Bucket policy granting ses.amazonaws.com s3:PutObject for this account."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowSESPuts",
                    "Effect": "Allow",
                    "Principal": {"Service": "ses.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                    "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
                }
            ],
        }
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An S3Action's KmsKeyArn is authorized apart from its bucket: a key granting SES nothing is
    refused (InvalidS3Configuration, distinct from a missing bucket, no rule stored); granting it
    makes the identical call succeed.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    recv_region = (
        ctx.region if ctx.region in _RECEIVING_REGIONS else _DEFAULT_RECEIVING_REGION
    )
    ses = ctx.client("ses", region=recv_region)
    kms = ctx.client("kms", region=recv_region)
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-ses-kms-inbound-")
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=_ses_bucket_policy(bucket, account))
    stored_bucket_policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    assert [s["Principal"]["Service"] for s in stored_bucket_policy["Statement"]] == [
        "ses.amazonaws.com"
    ], (
        f"setup precondition: the bucket must grant ses.amazonaws.com s3:PutObject, so the KMS key "
        f"is the only fault; GetBucketPolicy returned {stored_bucket_policy!r}"
    )

    key = kms.create_key(
        Description=f"sim2real {CHECK}",
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=_root_only_key_policy(account),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    # A KMS key cannot be deleted, only scheduled; 7 days is the documented minimum window.
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    stored_key_policy = json.loads(
        kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    )
    principals = [json.dumps(s["Principal"]) for s in stored_key_policy["Statement"]]
    assert not any("ses.amazonaws.com" in p for p in principals), (
        f"setup precondition: the key policy must grant SES nothing; GetKeyPolicy returned "
        f"principals {principals!r}"
    )

    rule_set = ctx.unique_name("sim2real-behav-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    rule = "s3-delivery"

    def _create_rule(*, with_key: bool, bucket_name: str | None = None):
        action: dict = {"BucketName": bucket_name or bucket}
        if with_key:
            action["KmsKeyArn"] = key_arn
        return ses.create_receipt_rule(
            RuleSetName=rule_set,
            Rule={
                "Name": rule,
                "Enabled": True,
                "ScanEnabled": False,
                "Actions": [{"S3Action": action}],
            },
        )

    # --- Positive control: the bucket grant works. Bounded because a new bucket policy can take
    #     minutes to begin matching a service principal.
    _poll_call(
        lambda: _create_rule(with_key=False),
        timeout_s=300,
        interval_s=10,
        description="CreateReceiptRule accepts the un-encrypted S3Action once the bucket grants "
        "ses.amazonaws.com s3:PutObject",
    )
    described = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=rule)["Rule"]
    assert "KmsKeyArn" not in described["Actions"][0]["S3Action"], (
        f"the control rule must carry no KmsKeyArn; DescribeReceiptRule returned "
        f"{described['Actions'][0]!r}"
    )
    ses.delete_receipt_rule(RuleSetName=rule_set, RuleName=rule)
    assert rule not in [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ], "the control rule must be gone before the negative leg reuses its name"

    # --- Break exactly one thing: the SAME rule, plus a key SES cannot use.
    kms_refused = _client_error(lambda: _create_rule(with_key=True))
    assert (kms_refused.get("Code"), kms_refused.get("Message")) == (
        "InvalidS3Configuration",
        f"Could not write to bucket: {bucket}",
    ), (
        f"an S3Action whose KmsKeyArn names a key that grants ses.amazonaws.com nothing must be "
        f"refused with InvalidS3Configuration; got {kms_refused.get('Code')!r}: "
        f"{kms_refused.get('Message')!r}"
    )

    # --- The KMS fault and the bucket fault must be told apart.
    ghost_bucket = ctx.unique_name("sim2real-behav-ses-ghost-bucket-")
    bucket_refused = _client_error(
        lambda: _create_rule(with_key=False, bucket_name=ghost_bucket)
    )
    assert (bucket_refused.get("Code"), bucket_refused.get("Message")) == (
        "InvalidS3Configuration",
        f"No such bucket: {ghost_bucket}",
    ), (
        f"a nonexistent bucket must also be InvalidS3Configuration (the incumbents' contract); got "
        f"{bucket_refused.get('Code')!r}: {bucket_refused.get('Message')!r}"
    )
    assert kms_refused != bucket_refused, (
        f"'the KMS key refuses SES' and 'the bucket does not exist' are different faults on the "
        f"same action and must not produce a byte-identical Error dict; both answered "
        f"{kms_refused!r}"
    )

    # --- Effect absent by an independent read.
    rules_now = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]
    ]
    assert rules_now == [], (
        f"neither refused CreateReceiptRule may persist a rule; DescribeReceiptRuleSet lists "
        f"{rules_now!r}"
    )

    # --- Restore: add the SES statement to the KEY policy. Nothing else changes.
    kms.put_key_policy(
        KeyId=key_id, PolicyName="default", Policy=_key_policy_with_ses(account)
    )
    restored_policy = json.loads(
        kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    )
    restored_principals = [json.dumps(s["Principal"]) for s in restored_policy["Statement"]]
    assert any("ses.amazonaws.com" in p for p in restored_principals), (
        f"the grant must be observably stored before anything is concluded from its effect; "
        f"GetKeyPolicy returned principals {restored_principals!r}"
    )

    # --- The identical call now succeeds once the key policy change propagates.
    _poll_call(
        lambda: _create_rule(with_key=True),
        timeout_s=180,
        interval_s=10,
        description="CreateReceiptRule accepts the encrypted S3Action once the key policy grants "
        "ses.amazonaws.com kms:Encrypt/GenerateDataKey*",
    )

    # --- Read back independently: the stored rule reports both bucket and key.
    final = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=rule)["Rule"]
    action = final["Actions"][0]["S3Action"]
    assert action["BucketName"] == bucket, (
        f"the stored action must name the granted bucket {bucket!r}, got {action!r}"
    )
    assert action["KmsKeyArn"] == key_arn, (
        f"the stored action must name the granted key {key_arn!r}, got {action!r}"
    )
    assert len(final["Actions"]) == 1, (
        f"expected exactly one action on {rule!r}, got {final['Actions']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
