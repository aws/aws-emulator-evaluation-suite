"""s3-action-object-key-prefix-and-kms-encryption."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-action-object-key-prefix-and-kms-encryption"
GROUP = "e2e"
SERVICES = ["s3", "ses", "sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_PREFIX = "sim2real-inbox/"

# ===== helpers =====


_POLL_INTERVAL_S = 2.0
_RESEND_AFTER_S = 20.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _receiving_domain(ctx, route53, sesv2):
    """The account's DNS baseline domain, the apex of its public hosted zone tagged
    _BASELINE_TAG, which SES has verified."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the receiving domain {domain!r} is not verified for SES in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "this account has no public hosted zone with the receiving-domain tag and so no "
        "domain to receive mail for"
    )


def _empty_and_delete(s3, bucket):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(
                f"bucket {bucket} not deleted: {exc.response['Error']['Code']}"
            ) from exc


def _retire_key(kms, key_id):
    """Re-enable then schedule deletion, so a mid-check failure never leaves a disabled key.

    7 days is the minimum PendingWindowInDays, so the key remains in PendingDeletion afterwards.
    """
    try:
        kms.enable_key(KeyId=key_id)
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except kms.exceptions.NotFoundException:
        pass


# ===== end helpers =====


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:e2e",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
    "resource:account-singleton:ses-active-receipt-rule-set",
)
def run(ctx) -> None:
    """A receipt rule's S3Action with both ObjectKeyPrefix and a customer KmsKeyArn writes the
    inbound message under that prefix, enveloped with that exact key via S3 client-side
    encryption, not S3 server-side SSE-KMS.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference/API_S3Action.html
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    ses = ctx.client("ses")
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    domain = _receiving_domain(ctx, route53, sesv2)

    bucket = ctx.unique_name("sim2real-ses-kms-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket))

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-ses-kms-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "s3-action-object-key-prefix-and-kms-encryption"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))

    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AccountRootFullAccess",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "AllowSESToEncryptInboundMail",
                        "Effect": "Allow",
                        "Principal": {"Service": "ses.amazonaws.com"},
                        "Action": ["kms:Encrypt", "kms:GenerateDataKey*", "kms:Decrypt"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {"AWS:SourceAccount": ctx.account}},
                    },
                ],
            }
        ),
    )

    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ses.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/{_PREFIX}*",
                        "Condition": {"StringEquals": {"AWS:SourceAccount": ctx.account}},
                    }
                ],
            }
        ),
    )

    recipient = f"{ctx.unique_name('sim2real-kmsto-')}@{domain}"
    sender = f"{ctx.unique_name('sim2real-kmsfrom-')}@{domain}"

    rule_set = ctx.unique_name("sim2real-ses-kms-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    grant_wait_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + grant_wait_s
    last_error = None
    while True:
        try:
            ses.create_receipt_rule(
                RuleSetName=rule_set,
                Rule={
                    "Name": "sim2real-kms-to-s3",
                    "Enabled": True,
                    "ScanEnabled": False,
                    "Recipients": [recipient],
                    "Actions": [
                        {
                            "S3Action": {
                                "BucketName": bucket,
                                "ObjectKeyPrefix": _PREFIX,
                                "KmsKeyArn": key_arn,
                            }
                        }
                    ],
                },
            )
            last_error = None
            break
        except ClientError as exc:
            last_error = exc
            if exc.response.get("Error", {}).get("Code") != "InvalidS3Configuration":
                raise
            if time.monotonic() >= deadline:
                break
            time.sleep(_POLL_INTERVAL_S)
    if last_error is not None and _budget_spent(ctx):
        raise TimeoutError("the KMS key grant to ses.amazonaws.com to propagate: the run budget ended first; not graded")
    assert last_error is None, (
        f"CreateReceiptRule with KmsKeyArn {key_arn!r} must succeed once the key policy's grant "
        f"to ses.amazonaws.com propagates within {grant_wait_s:.0f}s; last error was "
        f"{last_error.response['Error'] if last_error else None!r}"
    )

    previous = ses.describe_active_receipt_rule_set().get("Metadata", {}).get("Name")
    ses.set_active_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(
        lambda: ses.set_active_receipt_rule_set(**({"RuleSetName": previous} if previous else {}))
    )
    # No API reports when the new active set is live for the receiving MTA, so mail sent before it
    # is live can be dropped; the same message is re-sent while nothing has been captured.

    token = ctx.unique_name("sim2real-token-")

    def _send():
        sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [recipient]},
            Content={
                "Simple": {
                    "Subject": {"Data": token},
                    "Body": {"Text": {"Data": "sim2real s3-action-kms probe"}},
                }
            },
        )
        return time.monotonic()

    sent_at = _send()

    # Activating a rule set makes SES fire its own "Amazon SES Setup Notification" smoke test
    # addressed to the first rule's recipient; exclude it.
    wait_s = _budget_s(ctx, 600.0)
    deadline = time.monotonic() + wait_s
    received: list[str] = []
    while True:
        received = [
            o["Key"]
            for o in s3.list_objects_v2(Bucket=bucket, Prefix=_PREFIX).get("Contents", [])
            if not o["Key"].endswith("AMAZON_SES_SETUP_NOTIFICATION")
        ]
        if received or time.monotonic() >= deadline:
            break
        if time.monotonic() - sent_at >= _RESEND_AFTER_S:
            sent_at = _send()
        time.sleep(_POLL_INTERVAL_S)
    if not received and _budget_spent(ctx):
        raise TimeoutError(f"mail to {recipient!r} under {_PREFIX!r}: the run budget ended first; not graded")
    assert received, f"mail to {recipient!r} must be captured under {_PREFIX!r} within {wait_s:.0f}s"
    key_name = received[0]
    assert key_name.startswith(_PREFIX), (
        f"the stored object key {key_name!r} must start with the configured ObjectKeyPrefix "
        f"{_PREFIX!r}"
    )

    # SES uses the S3 encryption client, not SSE-KMS: the envelope shows up as x-amz-wrap-alg
    # and x-amz-matdesc object metadata, and the body is ciphertext.
    head = s3.head_object(Bucket=bucket, Key=key_name)
    metadata = head.get("Metadata", {})
    assert metadata.get("x-amz-wrap-alg") == "kms", (
        f"a KmsKeyArn'd S3Action must envelope-encrypt with the S3 encryption client "
        f"(x-amz-wrap-alg=kms); object metadata was {metadata!r}"
    )
    matdesc = json.loads(metadata.get("x-amz-matdesc", "{}"))
    assert matdesc.get("kms_cmk_id") == key_arn, (
        f"the envelope's material description must name the rule's configured key {key_arn!r}; "
        f"matdesc was {matdesc!r}"
    )
    assert matdesc.get("aws:ses:rule-name") == "sim2real-kms-to-s3", (
        f"the envelope's material description must name the triggering rule; matdesc was "
        f"{matdesc!r}"
    )

    raw = s3.get_object(Bucket=bucket, Key=key_name)["Body"].read()
    assert token.encode() not in raw, (
        f"the stored body must be the S3-encryption-client's ciphertext, not the plaintext "
        f"message; found the probe's own token {token!r} readable in it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
