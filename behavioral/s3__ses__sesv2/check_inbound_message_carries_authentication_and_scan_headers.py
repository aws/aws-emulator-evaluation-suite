"""inbound-message-carries-authentication-and-scan-headers."""

from __future__ import annotations

import email
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inbound-message-carries-authentication-and-scan-headers"
GROUP = "e2e"
SERVICES = ["s3", "ses", "sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}

# ===== helpers (self-contained) =====


_RESEND_AFTER_S = 20.0
_RECEIVE_TIMEOUT_S = 600.0
_RECEIVE_INTERVAL_S = 2.0


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
    """A receipt rule with ScanEnabled true adds Received-SPF, Authentication-Results and
    X-SES-Spam-Verdict / X-SES-Virus-Verdict to the stored raw message, and the DKIM result in
    Authentication-Results is dkim=pass for mail the verified domain sends to itself.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    ses = ctx.client("ses")
    s3 = ctx.client("s3")
    domain = _receiving_domain(ctx, route53, sesv2)

    bucket = ctx.unique_name("sim2real-ses-scan-")
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
                        "Resource": f"arn:aws:s3:::{bucket}/scan/*",
                        "Condition": {"StringEquals": {"AWS:SourceAccount": ctx.account}},
                    }
                ],
            }
        ),
    )

    recipient = f"{ctx.unique_name('sim2real-scanned-')}@{domain}"
    sender = f"{ctx.unique_name('sim2real-scansrc-')}@{domain}"

    rule_set = ctx.unique_name("sim2real-ses-scan-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={
            "Name": "sim2real-scan-to-s3",
            "Enabled": True,
            "ScanEnabled": True,
            "Recipients": [recipient],
            "Actions": [{"S3Action": {"BucketName": bucket, "ObjectKeyPrefix": "scan/"}}],
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

    def _send():
        sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [recipient]},
            Content={
                "Simple": {
                    "Subject": {"Data": token},
                    "Body": {"Text": {"Data": "sim2real scan-headers probe"}},
                }
            },
        )
        return time.monotonic()

    sent_at = _send()

    # Activating a rule set makes SES fire its own "Amazon SES Setup Notification" smoke test
    # addressed to the first rule's recipient; exclude it.
    receive_s = _budget_s(ctx, _RECEIVE_TIMEOUT_S)
    deadline = time.monotonic() + receive_s
    received: list[str] = []
    while time.monotonic() < deadline and not received:
        received = [
            o["Key"]
            for o in s3.list_objects_v2(Bucket=bucket, Prefix="scan/").get("Contents", [])
            if not o["Key"].endswith("AMAZON_SES_SETUP_NOTIFICATION")
        ]
        if not received:
            if time.monotonic() - sent_at >= _RESEND_AFTER_S:
                sent_at = _send()
            time.sleep(_RECEIVE_INTERVAL_S)
    if not received and _budget_spent(ctx):
        raise TimeoutError(f"mail to {recipient!r} under scan/: the run budget ended first; not graded")
    assert received, (
        f"mail to {recipient!r} on a ScanEnabled rule must be captured under scan/ within "
        f"{receive_s:.0f}s"
    )

    raw = s3.get_object(Bucket=bucket, Key=received[0])["Body"].read()
    msg = email.message_from_bytes(raw)
    assert msg["Subject"] == token, f"expected Subject {token!r}, got {msg['Subject']!r}"

    spf = msg.get_all("Received-SPF") or []
    assert spf, f"a ScanEnabled rule must stamp Received-SPF; headers were {list(msg.keys())!r}"

    auth_results = msg.get_all("Authentication-Results") or []
    assert auth_results, (
        f"a ScanEnabled rule must stamp Authentication-Results; headers were {list(msg.keys())!r}"
    )
    joined_auth = " ".join(auth_results)
    assert "dkim=pass" in joined_auth, (
        f"the domain's own verified DKIM signing must evaluate dkim=pass; "
        f"Authentication-Results was {auth_results!r}"
    )

    spam_verdict = msg.get_all("X-SES-Spam-Verdict") or []
    virus_verdict = msg.get_all("X-SES-Virus-Verdict") or []
    assert spam_verdict, (
        f"a ScanEnabled rule must stamp X-SES-Spam-Verdict; headers were {list(msg.keys())!r}"
    )
    assert virus_verdict, (
        f"a ScanEnabled rule must stamp X-SES-Virus-Verdict; headers were {list(msg.keys())!r}"
    )
    assert spam_verdict[0] in ("PASS", "FAIL"), (
        f"X-SES-Spam-Verdict must be a verdict token; got {spam_verdict!r}"
    )
    assert virus_verdict[0] in ("PASS", "FAIL"), (
        f"X-SES-Virus-Verdict must be a verdict token; got {virus_verdict!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
