"""mail-to-a-verified-domain-is-received-into-s3-by-a-receipt-rule."""

from __future__ import annotations

import email
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mail-to-a-verified-domain-is-received-into-s3-by-a-receipt-rule"
GROUP = "e2e"
SERVICES = ["s3", "ses", "sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}



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
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to receive mail for"
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




@tags("axis:happy-path", "cap:c2", "concern:e2e", "concern:data-plane", "dp:api", "plane:data", "requires:dns-baseline", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """Mail sent to an address on the account's verified domain is received through MX, matched
    by the active receipt rule set's recipient condition, and stored raw in S3 by its S3 action,
    DKIM-signed for the domain and carrying the probe's Subject.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    ses = ctx.client("ses")
    s3 = ctx.client("s3")
    domain = _receiving_domain(ctx, route53, sesv2)

    bucket = ctx.unique_name("sim2real-ses-inbound-")
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
                        "Resource": f"arn:aws:s3:::{bucket}/inbox/*",
                        "Condition": {"StringEquals": {"AWS:SourceAccount": ctx.account}},
                    }
                ],
            }
        ),
    )

    recipient = f"{ctx.unique_name('sim2real-in-')}@{domain}"
    rule_set = ctx.unique_name("sim2real-ses-inbound-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={
            "Name": "sim2real-to-s3",
            "Enabled": True,
            "ScanEnabled": False,
            "Recipients": [recipient],
            "Actions": [{"S3Action": {"BucketName": bucket, "ObjectKeyPrefix": "inbox/"}}],
        },
    )

    # Only one receipt rule set is active per account and region, so save and restore it.
    previous = ses.describe_active_receipt_rule_set().get("Metadata", {}).get("Name")
    ses.set_active_receipt_rule_set(RuleSetName=rule_set)
    # Registered after the set's delete, so it runs before it (cleanups run LIFO).
    ctx.on_cleanup(
        lambda: ses.set_active_receipt_rule_set(**({"RuleSetName": previous} if previous else {}))
    )

    token = ctx.unique_name("sim2real-token-")
    sender = f"{ctx.unique_name('sim2real-')}@{domain}"
    message_id = sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [recipient]},
        Content={
            "Simple": {"Subject": {"Data": token}, "Body": {"Text": {"Data": "inbound probe"}}}
        },
    )["MessageId"]

    # SES sends its own setup-notification message to a newly activated set; it is excluded.
    deadline = time.monotonic() + 300
    keys: list[str] = []
    received: list[str] = []
    while True:
        keys = [
            o["Key"] for o in s3.list_objects_v2(Bucket=bucket, Prefix="inbox/").get("Contents", [])
        ]
        received = [k for k in keys if k != "inbox/AMAZON_SES_SETUP_NOTIFICATION"]
        if received or time.monotonic() >= deadline:
            break
        time.sleep(2)
    active = ses.describe_active_receipt_rule_set().get("Metadata", {}).get("Name")
    assert len(received) == 1, (
        f"exactly one received message must land under inbox/ within 300s; got {received!r} "
        f"(all keys {keys!r}, SendEmail MessageId {message_id!r}, active rule set {active!r}, "
        f"expected {rule_set!r})"
    )
    keys = received

    raw = s3.get_object(Bucket=bucket, Key=keys[0])["Body"].read()
    msg = email.message_from_bytes(raw)
    assert msg["Subject"] == token, (
        f"the stored message must carry the probe's Subject {token!r}; got {msg['Subject']!r}"
    )
    assert recipient in (msg["To"] or ""), (
        f"the stored message must be addressed to {recipient!r}; To is {msg['To']!r}"
    )
    dkim = msg.get_all("DKIM-Signature") or []
    assert any(f"d={domain}" in sig.replace(" ", "") for sig in dkim), (
        f"SES must DKIM-sign mail from the verified domain with d={domain}; signatures {dkim!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
