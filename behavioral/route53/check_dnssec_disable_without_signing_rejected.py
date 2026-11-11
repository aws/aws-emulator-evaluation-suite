"""dnssec-disable-without-signing-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dnssec-disable-without-signing-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableHostedZoneDNSSEC on a zone that was never signed returns
    DNSSECNotFound, and the zone's DNSSEC status stays NOT_SIGNING."""
    route53 = ctx.client("route53")
    zone_id = _create_hosted_zone(ctx, route53)

    baseline = route53.get_dnssec(HostedZoneId=zone_id)
    assert baseline["Status"]["ServeSignature"] == "NOT_SIGNING"
    assert baseline["KeySigningKeys"] == []

    # Break exactly one thing: disable DNSSEC on a zone where it was never enabled.
    code, message = _error(lambda: route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id))
    assert code == "DNSSECNotFound", code
    expected = f"Couldn't find DNSSEC information for Hosted Zone with Id '{zone_id.split('/')[-1]}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: still NOT_SIGNING, no KSKs materialized.
    after = route53.get_dnssec(HostedZoneId=zone_id)
    assert after["Status"]["ServeSignature"] == "NOT_SIGNING"
    assert after["KeySigningKeys"] == []

    # Positive control in the same file: KSK management on this same zone
    # (create + GetDNSSEC) still works normally -- the rejection above is
    # specific to "there was never a signing config to disable", not a
    # blanket failure of the zone's DNSSEC subsystem.
    key_arn = _create_dnssec_kms_key(ctx)
    ksk_name = _ksk_name(ctx, "ctrl")
    _create_ksk(ctx, route53, zone_id, key_arn, ksk_name, "INACTIVE")
    control = _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda r: _ksk_status(r, ksk_name) == "INACTIVE",
        timeout_s=90,
    )
    assert _ksk_status(control, ksk_name) == "INACTIVE"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _ksk_status(dnssec_resp, name):
    for ksk in dnssec_resp.get("KeySigningKeys", []):
        if ksk["Name"] == name:
            return ksk["Status"]
    return None


def _ksk_name(ctx, suffix=""):
    raw = ctx.unique_name(f"sim2real-ksk-{suffix}-")
    return "k" + raw.replace("-", "_")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _dnssec_kms_key_policy(account_id):
    return json.dumps(
        {
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
                    "Sid": "AllowRoute53DNSSECService",
                    "Effect": "Allow",
                    "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                    "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
                    "Resource": "*",
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
    )


def _kms_client_us_east_1(ctx):
    """Route 53 DNSSEC requires the customer managed KMS key to live in us-east-1,
    regardless of the region under test."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx):
    kms = _kms_client_us_east_1(ctx)
    account_id = _account_id(ctx)
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_dnssec_kms_key_policy(account_id),
        Description="sim2real route53 DNSSEC behavioral check key",
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]

    def _cleanup():
        try:
            kms.disable_key(KeyId=key_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return key_arn


def _purge_ksks(route53, zone_id):
    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    for ksk in dnssec.get("KeySigningKeys", []):
        name = ksk["Name"]
        if ksk["Status"] == "ACTIVE":
            try:
                route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "HostedZoneNotFound",
                    "NoSuchHostedZone",
                    "NoSuchKeySigningKey",
                ):
                    raise
            _poll_until(
                lambda: route53.get_dnssec(HostedZoneId=zone_id),
                lambda r, n=name: _ksk_status(r, n) != "ACTIVE",
                timeout_s=60,
            )
        try:
            route53.delete_key_signing_key(HostedZoneId=zone_id, Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "HostedZoneNotFound",
                "NoSuchHostedZone",
                "NoSuchKeySigningKey",
            ):
                raise


def _create_hosted_zone(ctx, route53, name=None):
    zone_name = name or (ctx.unique_name("sim2real-r53-") + ".com.")
    zone = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=ctx.unique_name("sim2real-caller-"),
    )["HostedZone"]
    zone_id = zone["Id"]

    def _cleanup():
        try:
            _purge_ksks(route53, zone_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "HostedZoneNotFound",
                "NoSuchHostedZone",
                "NoSuchKeySigningKey",
            ):
                raise
        try:
            route53.delete_hosted_zone(Id=zone_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchHostedZone":
                raise

    ctx.on_cleanup(_cleanup)
    return zone_id


def _create_ksk(ctx, route53, zone_id, key_arn, name, status, timeout_s=120.0, interval_s=5.0):
    """CreateKeySigningKey can transiently fail with InvalidKMSArn while the
    freshly-created KMS key policy is still propagating; retry through that."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return route53.create_key_signing_key(
                CallerReference=ctx.unique_name("sim2real-ksk-cr-"),
                HostedZoneId=zone_id,
                KeyManagementServiceArn=key_arn,
                Name=name,
                Status=status,
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "InvalidKMSArn":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"CreateKeySigningKey never succeeded (KMS policy propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
