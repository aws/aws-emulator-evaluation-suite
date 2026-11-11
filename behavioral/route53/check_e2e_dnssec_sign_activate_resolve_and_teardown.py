"""e2e-dnssec-sign-activate-resolve-and-teardown."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-dnssec-sign-activate-resolve-and-teardown"
GROUP = "e2e"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Full DNSSEC lifecycle: sign with a KSK (GetDNSSEC shows DS and DNSKEY material), unwind
    to unsigned, delete the zone, and confirm GetHostedZone no longer finds it."""
    route53 = ctx.client("route53")

    zone_id, zone_name = _create_public_zone(ctx)
    key_arn = _create_dnssec_kms_key(ctx)

    ksk_name = "ksk" + uuid.uuid4().hex[:12]
    create_resp = route53.create_key_signing_key(
        CallerReference=ctx.unique_name("ksk-ref"),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=key_arn,
        Name=ksk_name,
        Status="INACTIVE",
    )
    _wait_change_insync(ctx, create_resp["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_ksk(ctx, zone_id, ksk_name))

    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    assert dnssec["KeySigningKeys"][0]["Status"] == "INACTIVE"

    # Activate the KSK.
    activate_resp = route53.activate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _wait_change_insync(ctx, activate_resp["ChangeInfo"]["Id"])

    ksk_status = _poll_until(
        probe=lambda: route53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"][0]["Status"],
        predicate=lambda s: s == "ACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert ksk_status == "ACTIVE", f"KSK never became ACTIVE, last status={ksk_status}"

    # Enable DNSSEC signing on the zone -- requires an ACTIVE KSK.
    enable_resp = route53.enable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _wait_change_insync(ctx, enable_resp["ChangeInfo"]["Id"])

    serve_signature = _poll_until(
        probe=lambda: route53.get_dnssec(HostedZoneId=zone_id)["Status"]["ServeSignature"],
        predicate=lambda s: s == "SIGNING",
        timeout_s=90,
        interval_s=5,
    )
    assert serve_signature == "SIGNING", f"zone never entered SIGNING, last={serve_signature}"

    final_dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    assert final_dnssec["Status"]["ServeSignature"] == "SIGNING"
    assert final_dnssec["KeySigningKeys"][0]["Status"] == "ACTIVE"
    assert final_dnssec["KeySigningKeys"][0]["Name"] == ksk_name
    assert final_dnssec["KeySigningKeys"][0]["DSRecord"], "no DS record published while SIGNING"
    assert final_dnssec["KeySigningKeys"][0]["DNSKEYRecord"], (
        "no DNSKEY record published while SIGNING"
    )

    # ---- Unwind: disable DNSSEC, deactivate + delete the KSK, back to unsigned ----
    disable_resp = route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _wait_change_insync(ctx, disable_resp["ChangeInfo"]["Id"])

    not_signing = _poll_until(
        probe=lambda: route53.get_dnssec(HostedZoneId=zone_id)["Status"]["ServeSignature"],
        predicate=lambda s: s == "NOT_SIGNING",
        timeout_s=90,
        interval_s=5,
    )
    assert not_signing == "NOT_SIGNING", f"zone never returned to NOT_SIGNING, last={not_signing}"

    deactivate_resp = route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _wait_change_insync(ctx, deactivate_resp["ChangeInfo"]["Id"])

    inactive_status = _poll_until(
        probe=lambda: route53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"][0]["Status"],
        predicate=lambda s: s == "INACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert inactive_status == "INACTIVE"

    delete_resp = route53.delete_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _wait_change_insync(ctx, delete_resp["ChangeInfo"]["Id"])

    final = route53.get_dnssec(HostedZoneId=zone_id)
    assert final["Status"]["ServeSignature"] == "NOT_SIGNING"
    assert final["KeySigningKeys"] == []

    # ---- The zone itself is now unsigned and deletable; delete it and prove it gone. ----
    route53.delete_hosted_zone(Id=zone_id)
    zone_gone = _poll_until(
        probe=lambda: _get_hosted_zone_error(route53, zone_id),
        predicate=lambda e: e["Code"] == "NoSuchHostedZone",
        timeout_s=60,
        interval_s=3,
    )
    assert zone_gone["Code"] == "NoSuchHostedZone", (
        f"hosted zone {zone_id} still resolves after DeleteHostedZone, error={zone_gone}"
    )
    assert zone_gone["Message"] == f"No hosted zone found with ID: {zone_id.split('/')[-1]}", zone_gone


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _wait_change_insync(ctx, change_id: str) -> None:
    route53 = ctx.client("route53")
    status = _poll_until(
        probe=lambda: route53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        predicate=lambda s: s == "INSYNC",
        timeout_s=120,
        interval_s=5,
    )
    assert status == "INSYNC", f"change {change_id} never reached INSYNC, last={status}"


def _create_public_zone(ctx) -> tuple[str, str]:
    route53 = ctx.client("route53")
    zone_name = f"{ctx.unique_name('sim2real-dnssec-zone')}.com.".replace("_", "-")
    resp = route53.create_hosted_zone(
        Name=zone_name, CallerReference=ctx.unique_name("dnssec-zone-ref")
    )
    zone_id = resp["HostedZone"]["Id"]
    _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_zone(ctx, zone_id))
    return zone_id, zone_name


def _kms_client_for_dnssec(ctx):
    """A KMS client in us-east-1: Route 53 DNSSEC accepts only a customer managed key there,
    whatever region the run targets."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx) -> str:
    kms = _kms_client_for_dnssec(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
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
                "Sid": "AllowRoute53DNSSECCreateGrant",
                "Effect": "Allow",
                "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                "Action": ["kms:CreateGrant"],
                "Resource": "*",
                "Condition": {"Bool": {"kms:GrantIsForAWSResource": True}},
            },
        ],
    }
    resp = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "Name", "TagValue": ctx.unique_name("sim2real-dnssec-key")}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_arn


def _safe_delete_ksk(ctx, zone_id: str, name: str) -> None:
    route53 = ctx.client("route53")
    try:
        dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("HostedZoneNotFound", "NoSuchHostedZone"):
            raise
        return
    ksks = {k["Name"]: k for k in dnssec.get("KeySigningKeys", [])}
    if name not in ksks:
        return
    try:
        if dnssec["Status"]["ServeSignature"] == "SIGNING":
            resp = route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
            _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DNSSECNotFound",
            "HostedZoneNotFound",
            "NoSuchChange",
            "NoSuchHostedZone",
        ):
            raise
    try:
        if ksks[name]["Status"] == "ACTIVE":
            resp = route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
            _wait_change_insync(ctx, resp["ChangeInfo"]["Id"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchChange",
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


def _safe_delete_zone(ctx, zone_id: str) -> None:
    route53 = ctx.client("route53")
    try:
        route53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _get_hosted_zone_error(route53, zone_id: str) -> dict:
    """The ``Error`` GetHostedZone raises for ``zone_id``; a zone still readable yields an
    ``Error`` whose code no AWS error carries, so the poll keeps waiting and never passes."""
    try:
        route53.get_hosted_zone(Id=zone_id)
    except ClientError as e:
        return e.response["Error"]
    return {"Code": "<zone still readable>", "Message": ""}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
