"""e2e-dnssec-enable-verify-disable-teardown."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-dnssec-enable-verify-disable-teardown"
GROUP = "e2e"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling DNSSEC signing on a zone that has an ACTIVE key-signing key produces
    a DS record visible via GetDNSSEC; disabling signing and then deleting the KSK
    cleanly removes all DNSSEC state from the zone."""
    route53 = ctx.client("route53")

    zone_name = f"{ctx.unique_name('sim2real-dnssec-')}.com."
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

    activate = route53.activate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _poll_change_insync(ctx, activate["ChangeInfo"]["Id"])

    enable = route53.enable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _poll_change_insync(ctx, enable["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_disable_dnssec(ctx, zone_id))

    dnssec = _poll_dnssec_status(ctx, zone_id, "SIGNING", timeout_s=240.0)
    ksk_entry = next(k for k in dnssec["KeySigningKeys"] if k["Name"] == ksk_name)
    assert ksk_entry["Status"] == "ACTIVE", (
        f"expected KSK {ksk_name} Status=ACTIVE once signing, got {ksk_entry['Status']!r}"
    )
    assert ksk_entry["DSRecord"], f"expected a non-empty DSRecord for {ksk_name}, got {ksk_entry['DSRecord']!r}"
    assert ksk_entry["DNSKEYRecord"], (
        f"expected a non-empty DNSKEYRecord for {ksk_name}, got {ksk_entry['DNSKEYRecord']!r}"
    )

    disable = route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _poll_change_insync(ctx, disable["ChangeInfo"]["Id"])
    _poll_dnssec_status(ctx, zone_id, "NOT_SIGNING", timeout_s=180.0)

    deactivate = route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _poll_change_insync(ctx, deactivate["ChangeInfo"]["Id"])

    def _ksk_status():
        d = route53.get_dnssec(HostedZoneId=zone_id)
        return next(k for k in d["KeySigningKeys"] if k["Name"] == ksk_name)["Status"]

    _poll_until(_ksk_status, lambda s: s == "INACTIVE", timeout_s=90.0, interval_s=5.0)

    delete_ksk = route53.delete_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _poll_change_insync(ctx, delete_ksk["ChangeInfo"]["Id"])

    def _ksk_gone():
        d = route53.get_dnssec(HostedZoneId=zone_id)
        return not any(k["Name"] == ksk_name for k in d["KeySigningKeys"])

    _poll_until(_ksk_gone, lambda gone: gone, timeout_s=60.0, interval_s=5.0)

    final = route53.get_dnssec(HostedZoneId=zone_id)
    assert not any(k["Name"] == ksk_name for k in final["KeySigningKeys"]), (
        f"expected {ksk_name} absent from GetDNSSEC after DeleteKeySigningKey, "
        f"still present: {[k['Name'] for k in final['KeySigningKeys']]}"
    )
    assert final["Status"]["ServeSignature"] == "NOT_SIGNING", (
        f"expected ServeSignature=NOT_SIGNING after teardown, got {final['Status']['ServeSignature']!r}"
    )

    route53.delete_hosted_zone(Id=zone_id)

    def _zone_gone():
        try:
            route53.get_hosted_zone(Id=zone_id)
            return False
        except ClientError as e:
            return e.response["Error"]["Code"] == "NoSuchHostedZone"

    _poll_until(_zone_gone, lambda gone: gone, timeout_s=60.0, interval_s=5.0)


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
