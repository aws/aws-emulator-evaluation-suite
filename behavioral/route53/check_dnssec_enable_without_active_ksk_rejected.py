"""dnssec-enable-without-active-ksk-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dnssec-enable-without-active-ksk-rejected"
GROUP = "e2e"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableHostedZoneDNSSEC is rejected with KeySigningKeyWithActiveStatusNotFound
    when the zone has no ACTIVE key-signing key, the zone stays NOT_SIGNING, and the
    very same zone can enable successfully once its KSK is activated (control)."""
    route53 = ctx.client("route53")

    zone_name = f"{ctx.unique_name('sim2real-dnssecneg-')}.com."
    zone = route53.create_hosted_zone(
        Name=zone_name, CallerReference=ctx.unique_name("caller-")
    )
    zone_id = zone["HostedZone"]["Id"]
    _poll_change_insync(ctx, zone["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_zone(ctx, zone_id))

    kms_key = _create_dnssec_kms_key(ctx)
    ksk_name = ctx.unique_name("ksk-").replace("-", "_")
    ksk = _create_ksk_with_retry(ctx, zone_id, kms_key["arn"], ksk_name, "INACTIVE")
    _poll_change_insync(ctx, ksk["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_ksk(ctx, zone_id, ksk_name))

    # break exactly one thing: try to enable DNSSEC while the only KSK is INACTIVE
    code, message = _error(lambda: route53.enable_hosted_zone_dnssec(HostedZoneId=zone_id))
    assert code == "KeySigningKeyWithActiveStatusNotFound", (
        f"expected KeySigningKeyWithActiveStatusNotFound when enabling DNSSEC with only an "
        f"INACTIVE key-signing key, got {code!r}"
    )
    expected = (
        f"Hosted zone with ID '{zone_id.split('/')[-1]}' does not have a Key Signing Key in "
        "ACTIVE status."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the zone is still not signing
    still_not_signing = route53.get_dnssec(HostedZoneId=zone_id)
    serve = still_not_signing["Status"]["ServeSignature"]
    assert serve == "NOT_SIGNING", (
        f"expected ServeSignature NOT_SIGNING after the rejected EnableHostedZoneDNSSEC call, "
        f"got {serve!r}"
    )

    # positive control: activating the KSK first lets the identical call succeed
    activate = route53.activate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _poll_change_insync(ctx, activate["ChangeInfo"]["Id"])

    enable = route53.enable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _poll_change_insync(ctx, enable["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_disable_dnssec(ctx, zone_id))

    dnssec = _poll_dnssec_status(ctx, zone_id, "SIGNING", timeout_s=240.0)
    serve_signing = dnssec["Status"]["ServeSignature"]
    assert serve_signing == "SIGNING", (
        f"expected ServeSignature SIGNING once the KSK was activated and the identical "
        f"EnableHostedZoneDNSSEC call repeated, got {serve_signing!r}"
    )

    disable = route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _poll_change_insync(ctx, disable["ChangeInfo"]["Id"])
    _poll_dnssec_status(ctx, zone_id, "NOT_SIGNING", timeout_s=180.0)


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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


def _poll_dnssec_status(ctx, zone_id, target, timeout_s=180.0):
    route53 = ctx.client("route53")
    return _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda d: d["Status"]["ServeSignature"] == target,
        timeout_s=timeout_s,
        interval_s=10.0,
    )


def _kms_client_us_east_1(ctx):
    """Route 53 DNSSEC requires the customer managed KMS key to live in us-east-1,
    regardless of the region under test."""
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


def _safe_disable_dnssec(ctx, zone_id) -> None:
    route53 = ctx.client("route53")
    try:
        route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DNSSECNotFound",
            "HostedZoneNotFound",
            "NoSuchHostedZone",
        ):
            raise


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
