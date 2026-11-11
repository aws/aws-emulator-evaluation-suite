"""dnssec-enable-disable-state-reflected-in-getdnssec."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dnssec-enable-disable-state-reflected-in-getdnssec"
GROUP = "state-machine"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enable then Disable DNSSEC flips GetDNSSEC's Status.ServeSignature SIGNING and back.

    A fresh zone with an ACTIVE KSK starts NOT_SIGNING and returns to NOT_SIGNING after disable.
    """
    route53 = ctx.client("route53")
    zone_id = _create_public_hosted_zone(ctx)

    kms_arn = _create_dnssec_kms_key(ctx)
    name = _ksk_name(ctx, "flip")

    route53.create_key_signing_key(
        CallerReference=ctx.unique_name("sim2real-r53-cr-"),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=kms_arn,
        Name=name,
        Status="ACTIVE",
    )
    ctx.on_cleanup(_deactivate_and_delete_ksk(ctx, zone_id, name))
    _poll_ksk_status(ctx, zone_id, name, "ACTIVE")

    baseline = route53.get_dnssec(HostedZoneId=zone_id)
    baseline_signature = baseline["Status"]["ServeSignature"]
    assert baseline_signature == "NOT_SIGNING", (
        f"expected fresh zone ServeSignature NOT_SIGNING, got {baseline_signature!r}"
    )

    # HostedZonePartiallyDelegated only fires against a resolvable parent domain; an
    # unregistered zone name has none, so enabling succeeds on a fresh zone.
    route53.enable_hosted_zone_dnssec(HostedZoneId=zone_id)
    ctx.on_cleanup(lambda: _safe(lambda: route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id), "DNSSECNotFound", "NoSuchHostedZone"))
    _poll_serve_signature(ctx, zone_id, "SIGNING")

    route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _poll_serve_signature(ctx, zone_id, "NOT_SIGNING")


def _safe(fn, *gone: str) -> None:
    """Teardown call: return on the listed not-found codes, raise every other failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone:
            raise


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _dnssec_kms_key_policy(account_id: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableIAMUserPermissions",
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
                    "Sid": "AllowRoute53DNSSECServiceToCreateGrant",
                    "Effect": "Allow",
                    "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                    "Action": ["kms:CreateGrant"],
                    "Resource": "*",
                    "Condition": {"Bool": {"kms:GrantIsForAWSResource": True}},
                },
            ],
        }
    )


def _dnssec_kms_client(ctx):
    """Route 53 DNSSEC only accepts a customer managed KMS key that lives in us-east-1,
    regardless of the check's default client region."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx) -> str:
    kms = _dnssec_kms_client(ctx)
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_dnssec_kms_key_policy(_account_id(ctx)),
        Description="sim2real-behav route53 dnssec test key",
        Tags=[{"TagKey": "sim2real", "TagValue": "route53-dnssec"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7), "NotFoundException")
    )
    return key["Arn"]


def _create_public_hosted_zone(ctx) -> str:
    route53 = ctx.client("route53")
    name = ctx.unique_name("sim2real-r53-ksk-") + ".com."
    resp = route53.create_hosted_zone(
        Name=name, CallerReference=ctx.unique_name("sim2real-r53-cr-")
    )
    zone_id = resp["HostedZone"]["Id"].split("/")[-1]
    ctx.on_cleanup(lambda: _safe(lambda: route53.delete_hosted_zone(Id=zone_id), "NoSuchHostedZone"))
    return zone_id


def _ksk_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"ksk{tag}")
    return re.sub(r"[^0-9A-Za-z_]", "_", raw)[:128]


def _find_ksk(dnssec_resp, name: str):
    for ksk in dnssec_resp.get("KeySigningKeys", []):
        if ksk["Name"] == name:
            return ksk
    return None


def _poll_ksk_status(ctx, zone_id: str, name: str, expected: str, timeout_s: float = 90.0, interval_s: float = 3.0):
    route53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = route53.get_dnssec(HostedZoneId=zone_id)
        ksk = _find_ksk(resp, name)
        if ksk is not None:
            last = ksk["Status"]
            if last == expected:
                return ksk
        time.sleep(interval_s)
    raise AssertionError(f"KSK {name} never reached status {expected}, last seen {last}")


def _poll_serve_signature(ctx, zone_id: str, expected: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    route53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = route53.get_dnssec(HostedZoneId=zone_id)
        last = resp["Status"]["ServeSignature"]
        if last == expected:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"Status.ServeSignature never reached {expected}, last seen {last}")


def _deactivate_and_delete_ksk(ctx, zone_id: str, name: str):
    route53 = ctx.client("route53")

    def _cleanup() -> None:
        _poll_serve_signature(ctx, zone_id, "NOT_SIGNING", timeout_s=180.0, interval_s=2.0)
        # Route 53 refuses deactivating the only ACTIVE KSK while the zone still signs.
        deadline = time.monotonic() + 60.0
        while True:
            try:
                route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchKeySigningKey":
                    return
                if code == "InvalidKeySigningKeyStatus":
                    break
                if code != "KeySigningKeyInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        _poll_ksk_status(ctx, zone_id, name, "INACTIVE", timeout_s=60, interval_s=2.0)
        _safe(lambda: route53.delete_key_signing_key(HostedZoneId=zone_id, Name=name), "NoSuchKeySigningKey")

    return _cleanup


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
