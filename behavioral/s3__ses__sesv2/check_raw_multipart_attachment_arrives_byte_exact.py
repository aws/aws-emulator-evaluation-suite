"""raw-multipart-attachment-arrives-byte-exact."""

from __future__ import annotations

import email
import hashlib
import json
import time
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "raw-multipart-attachment-arrives-byte-exact"
GROUP = "e2e"
SERVICES = ["s3", "ses", "sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_ATTACHMENT_BYTES = bytes(range(256)) * 4  # arbitrary binary payload, not valid text
_ATTACHMENT_FILENAME_PREFIX = "sim2real-attach-"

# ===== helpers (self-contained) =====


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
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}; "
                    "verify it in SES before running this check"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag) and so no domain to receive mail for; the check requires one"
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


# ===== end helpers =====


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:e2e",
    "concern:representation",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
    "resource:account-singleton:ses-active-receipt-rule-set",
)
def run(ctx) -> None:
    """SendRawEmail's binary attachment survives inbound delivery byte-for-byte: the stored MIME
    part decodes to the identical SHA-256, and its Content-Type and filename are unchanged.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    ses = ctx.client("ses")
    s3 = ctx.client("s3")
    domain = _receiving_domain(ctx, route53, sesv2)

    bucket = ctx.unique_name("sim2real-ses-attach-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket))
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
                        "Resource": f"arn:aws:s3:::{bucket}/raw/*",
                        "Condition": {"StringEquals": {"AWS:SourceAccount": ctx.account}},
                    }
                ],
            }
        ),
    )

    recipient = f"{ctx.unique_name('sim2real-attachto-')}@{domain}"
    sender = f"{ctx.unique_name('sim2real-attachfrom-')}@{domain}"

    rule_set = ctx.unique_name("sim2real-ses-attach-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={
            "Name": "sim2real-attach-to-s3",
            "Enabled": True,
            "ScanEnabled": False,
            "Recipients": [recipient],
            "Actions": [{"S3Action": {"BucketName": bucket, "ObjectKeyPrefix": "raw/"}}],
        },
    )

    previous = ses.describe_active_receipt_rule_set().get("Metadata", {}).get("Name")
    ses.set_active_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(
        lambda: ses.set_active_receipt_rule_set(**({"RuleSetName": previous} if previous else {}))
    )
    # No API reports when the new active set is live for the receiving MTA, so mail sent before it
    # is live can be dropped; the same message is re-sent while nothing has been captured.

    token = ctx.unique_name("sim2real-token-")
    filename = f"{_ATTACHMENT_FILENAME_PREFIX}{token}.bin"
    outer = MIMEMultipart()
    outer["From"] = sender
    outer["To"] = recipient
    outer["Subject"] = token
    outer.attach(MIMEText("sim2real raw multipart attachment probe", "plain"))
    attachment = MIMEApplication(_ATTACHMENT_BYTES, _subtype="octet-stream")
    attachment.add_header("Content-Disposition", "attachment", filename=filename)
    outer.attach(attachment)

    def _send():
        ses.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={"Data": outer.as_bytes()},
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
            for o in s3.list_objects_v2(Bucket=bucket, Prefix="raw/").get("Contents", [])
            if not o["Key"].endswith("AMAZON_SES_SETUP_NOTIFICATION")
        ]
        if received or time.monotonic() >= deadline:
            break
        if time.monotonic() - sent_at >= _RESEND_AFTER_S:
            sent_at = _send()
        time.sleep(_POLL_INTERVAL_S)
    if not received and _budget_spent(ctx):
        raise TimeoutError(f"mail to {recipient!r} under raw/: the run budget ended first; not graded")
    assert received, f"mail to {recipient!r} must be captured under raw/ within {wait_s:.0f}s"

    raw = s3.get_object(Bucket=bucket, Key=received[0])["Body"].read()
    msg = email.message_from_bytes(raw)
    assert msg["Subject"] == token, f"expected Subject {token!r}, got {msg['Subject']!r}"

    attachment_part = None
    for part in msg.walk():
        if part.get_filename() == filename:
            attachment_part = part
            break
    assert attachment_part is not None, (
        f"no stored MIME part carries the sent filename {filename!r}; filenames seen were "
        f"{[p.get_filename() for p in msg.walk()]!r}"
    )
    assert attachment_part.get_content_type() == "application/octet-stream", (
        f"expected Content-Type application/octet-stream, got "
        f"{attachment_part.get_content_type()!r}"
    )
    decoded = attachment_part.get_payload(decode=True)
    assert hashlib.sha256(decoded).hexdigest() == hashlib.sha256(_ATTACHMENT_BYTES).hexdigest(), (
        f"the decoded attachment ({len(decoded)} bytes) must be byte-identical to what was "
        f"sent ({len(_ATTACHMENT_BYTES)} bytes)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
