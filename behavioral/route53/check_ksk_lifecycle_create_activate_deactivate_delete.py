"""ksk-lifecycle-create-activate-deactivate-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ksk-lifecycle-create-activate-deactivate-delete"
GROUP = "state-machine"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A KSK transitions INACTIVE->ACTIVE->INACTIVE and is only deletable while
    INACTIVE, with GetDNSSEC accurately reflecting each state."""
    route53 = ctx.client("route53")
    key_arn = _create_dnssec_kms_key(ctx)
    zone_id = _create_hosted_zone(ctx, route53)
    ksk_name = _ksk_name(ctx, "lc")

    _create_ksk(ctx, route53, zone_id, key_arn, ksk_name, "INACTIVE")
    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    status = _ksk_status(dnssec, ksk_name)
    assert status == "INACTIVE", f"expected freshly-created KSK {ksk_name} INACTIVE, got {status!r}"

    route53.activate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    dnssec = _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda r: _ksk_status(r, ksk_name) == "ACTIVE",
        timeout_s=90,
    )
    status = _ksk_status(dnssec, ksk_name)
    assert status == "ACTIVE", f"expected KSK {ksk_name} ACTIVE after ActivateKeySigningKey, got {status!r}"

    route53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    dnssec = _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda r: _ksk_status(r, ksk_name) == "INACTIVE",
        timeout_s=90,
    )
    status = _ksk_status(dnssec, ksk_name)
    assert status == "INACTIVE", f"expected KSK {ksk_name} INACTIVE after DeactivateKeySigningKey, got {status!r}"

    # Only deletable once INACTIVE -- this must now succeed.
    route53.delete_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    dnssec = _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda r: _ksk_status(r, ksk_name) is None,
        timeout_s=90,
    )
    status = _ksk_status(dnssec, ksk_name)
    assert status is None, f"expected KSK {ksk_name} absent from GetDNSSEC after delete, got status {status!r}"

    # gone and unusable: the dead id does not re-accept the same mutation, it fails not-found
    dead_code, dead_message = _client_error(lambda: route53.delete_key_signing_key(HostedZoneId=zone_id, Name=ksk_name))
    assert dead_code == "NoSuchKeySigningKey", f"expected NoSuchKeySigningKey on dead KSK, got {dead_code!r}"
    expected_message = f"The Key Signing Key with name '{ksk_name}', could not be found."
    assert dead_message == expected_message, f"expected message {expected_message!r}, got {dead_message!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


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
    """Route 53 DNSSEC requires the customer managed KMS key (and the
    CreateKeySigningKey call itself) to target us-east-1 regardless of the
    region under test (see the AWS CLI DNSSEC setup guide, which pins
    `--region us-east-1`)."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx):
    kms = _kms_client_us_east_1(ctx)
    account_id = _account_id(ctx)
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_dnssec_kms_key_policy(account_id),
        Description="sim2real route53 DNSSEC behavioral check key",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
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
    bare_zone_id = zone_id.split("/")[-1]
    route53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=bare_zone_id, AddTags=[{"Key": "sim2real", "Value": CHECK}]
    )

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
