"""ds-record-base64-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ds-record-base64-round-trip"
GROUP = "representation"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The DNSKEY/DS record bytes (and the KeyTag/PublicKey/DigestValue that derive
    from them) returned for a KSK by repeated GetDNSSEC calls are byte-identical to
    the values generated at CreateKeySigningKey time."""
    route53 = ctx.client("route53")

    zone_name = f"{ctx.unique_name('sim2real-dsrep-')}.com."
    zone = route53.create_hosted_zone(
        Name=zone_name, CallerReference=ctx.unique_name("caller-")
    )
    zone_id = zone["HostedZone"]["Id"]
    _poll_change_insync(ctx, zone["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_zone(ctx, zone_id))

    kms_key = _create_dnssec_kms_key(ctx)
    ksk_name = ctx.unique_name("ksk-").replace("-", "_")
    created = _create_ksk_with_retry(ctx, zone_id, kms_key["arn"], ksk_name, "ACTIVE")
    _poll_change_insync(ctx, created["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_ksk(ctx, zone_id, ksk_name))

    created_ksk = created["KeySigningKey"]

    # Three independent GetDNSSEC reads spaced 2s apart, not a single immediate re-read, so a
    # target that re-derives the material lazily (rather than returning the stored bytes) has
    # time to drift between calls instead of hitting a request-local cache.
    first, *rest = _reads_over_time(ctx, zone_id, ksk_name, count=3, interval_s=2.0)

    for field in ("DSRecord", "DNSKEYRecord", "PublicKey", "DigestValue", "KeyTag"):
        creation_value = created_ksk[field]
        first_value = first[field]
        assert first_value == creation_value, (
            f"{field} differs between CreateKeySigningKey ({creation_value!r}) and the "
            f"first GetDNSSEC read ({first_value!r})"
        )
        for idx, read in enumerate(rest, start=2):
            read_value = read[field]
            assert read_value == creation_value, (
                f"{field} differs between CreateKeySigningKey ({creation_value!r}) and "
                f"GetDNSSEC read #{idx} ({read_value!r})"
            )


def _get_ksk(ctx, zone_id, name) -> dict:
    route53 = ctx.client("route53")
    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    return next(k for k in dnssec["KeySigningKeys"] if k["Name"] == name)


def _reads_over_time(ctx, zone_id, name, *, count, interval_s) -> list[dict]:
    reads = []
    for i in range(count):
        if i > 0:
            time.sleep(interval_s)
        reads.append(_get_ksk(ctx, zone_id, name))
    return reads


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_change_insync(ctx, change_id, timeout_s=120.0) -> None:
    route53 = ctx.client("route53")
    _poll_until(
        lambda: route53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda s: s == "INSYNC",
        timeout_s=timeout_s,
        interval_s=3.0,
    )


def _kms_client_us_east_1(ctx):
    """A KMS client in us-east-1: Route 53 DNSSEC accepts only a customer managed key there,
    whatever region the run targets."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx) -> dict:
    kms = _kms_client_us_east_1(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowRoute53DNSSECUse",
                "Effect": "Allow",
                "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AllowRoute53DNSSECCreateGrant",
                "Effect": "Allow",
                "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                "Action": "kms:CreateGrant",
                "Resource": "*",
                "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}},
            },
        ],
    }
    resp = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "route53-dnssec"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]

    def _cleanup():
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"id": key_id, "arn": resp["KeyMetadata"]["Arn"]}


def _create_ksk_with_retry(ctx, zone_id, kms_arn, name, status):
    route53 = ctx.client("route53")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return route53.create_key_signing_key(
                CallerReference=ctx.unique_name("ksk-ref-"),
                HostedZoneId=zone_id,
                KeyManagementServiceArn=kms_arn,
                Name=name,
                Status=status,
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidKMSArn" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _safe_delete_ksk(ctx, zone_id, name) -> None:
    route53 = ctx.client("route53")
    try:
        route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHostedZone",
            "NoSuchKeySigningKey",
        ):
            raise
    try:
        route53.delete_key_signing_key(HostedZoneId=zone_id, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHostedZone",
            "NoSuchKeySigningKey",
        ):
            raise


def _safe_delete_zone(ctx, zone_id) -> None:
    route53 = ctx.client("route53")
    try:
        route53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
