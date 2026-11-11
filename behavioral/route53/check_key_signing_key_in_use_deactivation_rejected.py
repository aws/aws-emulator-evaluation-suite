"""key-signing-key-in-use-deactivation-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "key-signing-key-in-use-deactivation-rejected"
GROUP = "e2e"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deactivating the sole ACTIVE KSK while signing is enabled fails with KeySigningKeyInUse
    and the KSK stays ACTIVE; the same deactivation succeeds once signing is disabled."""
    route53 = ctx.client("route53")

    zone_id, _zone_name = _create_public_zone(ctx)
    key_arn = _create_dnssec_kms_key(ctx)

    ksk_name = "ksk" + uuid.uuid4().hex[:12]
    create_resp = route53.create_key_signing_key(
        CallerReference=ctx.unique_name("ksk-ref"),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=key_arn,
        Name=ksk_name,
        Status="ACTIVE",
    )
    _wait_change_insync(ctx, create_resp["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _safe_delete_ksk(ctx, zone_id, ksk_name))

    enable_resp = route53.enable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _wait_change_insync(ctx, enable_resp["ChangeInfo"]["Id"])

    serve_signature = _poll_until(
        probe=lambda: route53.get_dnssec(HostedZoneId=zone_id)["Status"]["ServeSignature"],
        predicate=lambda s: s == "SIGNING",
        timeout_s=90,
        interval_s=5,
    )
    assert serve_signature == "SIGNING", f"zone never entered SIGNING, last={serve_signature}"

    # --- break exactly one thing: deactivate the only ACTIVE KSK while still signing ---
    err = _client_error(
        lambda: route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    )
    assert err["Code"] == "KeySigningKeyInUse"
    assert err["Message"] == (
        f"Key Signing Key with name '{ksk_name}' is the only available ACTIVE key for the hosted zone."
    ), err

    # --- effect must be absent: the KSK is still ACTIVE and the zone is still signing ---
    dnssec_after_rejection = route53.get_dnssec(HostedZoneId=zone_id)
    still_active = dnssec_after_rejection["KeySigningKeys"][0]["Status"]
    assert still_active == "ACTIVE"
    still_signing = dnssec_after_rejection["Status"]["ServeSignature"]
    assert still_signing == "SIGNING", f"expected signing to continue, got {still_signing}"

    # --- positive control: disable signing first, then the same deactivation succeeds ---
    disable_resp = route53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _wait_change_insync(ctx, disable_resp["ChangeInfo"]["Id"])
    _poll_until(
        probe=lambda: route53.get_dnssec(HostedZoneId=zone_id)["Status"]["ServeSignature"],
        predicate=lambda s: s == "NOT_SIGNING",
        timeout_s=90,
        interval_s=5,
    )

    deactivate_resp = route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    _wait_change_insync(ctx, deactivate_resp["ChangeInfo"]["Id"])

    final_status = _poll_until(
        probe=lambda: route53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"][0]["Status"],
        predicate=lambda s: s == "INACTIVE",
        timeout_s=60,
        interval_s=3,
    )
    assert final_status == "INACTIVE", f"KSK never deactivated once unsigned, last={final_status}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for condition, last={last!r}")


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    zone_name = f"{ctx.unique_name('sim2real-ksk-inuse-zone')}.com.".replace("_", "-")
    resp = route53.create_hosted_zone(
        Name=zone_name, CallerReference=ctx.unique_name("ksk-inuse-zone-ref")
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
        Tags=[{"TagKey": "Name", "TagValue": ctx.unique_name("sim2real-ksk-inuse-key")}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
