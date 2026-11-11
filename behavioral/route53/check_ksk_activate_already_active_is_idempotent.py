"""ksk-activate-already-active-is-idempotent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ksk-activate-already-active-is-idempotent"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-activating an ACTIVE KSK is an idempotent success that leaves it ACTIVE.

    Activating a KSK name never created on the zone is rejected; activating an INACTIVE KSK works.
    """
    route53 = ctx.client("route53")
    key_arn = _create_dnssec_kms_key(ctx)
    zone_id = _create_hosted_zone(ctx, route53)

    ksk_a = _ksk_name(ctx, "a")
    _create_ksk(ctx, route53, zone_id, key_arn, ksk_a, "ACTIVE")
    dnssec = _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda r: _ksk_status(r, ksk_a) == "ACTIVE",
        timeout_s=90,
    )
    status = _ksk_status(dnssec, ksk_a)
    assert status == "ACTIVE", f"expected ksk_a ACTIVE after create, got {status!r}"

    # Re-activating an already-ACTIVE KSK is accepted idempotently, not
    # rejected -- and leaves exactly one ACTIVE entry, no duplication.
    route53.activate_key_signing_key(HostedZoneId=zone_id, Name=ksk_a)
    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    status = _ksk_status(dnssec, ksk_a)
    assert status == "ACTIVE", f"expected ksk_a still ACTIVE after idempotent re-activate, got {status!r}"
    matches = [k for k in dnssec["KeySigningKeys"] if k["Name"] == ksk_a]
    assert len(matches) == 1, f"expected exactly one KSK named {ksk_a!r}, got {len(matches)}: {matches!r}"

    # Break exactly one thing: activate a KSK name that was never created on
    # this hosted zone -- a genuinely invalid target must be rejected.
    bogus_name = _ksk_name(ctx, "bogus")
    err = _client_error(
        lambda: route53.activate_key_signing_key(HostedZoneId=zone_id, Name=bogus_name)
    )
    assert err["Code"] == "NoSuchKeySigningKey", f"unexpected code: {err}"
    assert err["Message"] == f"The Key Signing Key with name '{bogus_name}', could not be found.", err

    # Positive control in the same file: activating a genuinely INACTIVE KSK
    # in the same hosted zone succeeds and transitions to ACTIVE. A zone
    # can't have two KSKs backed by the same KMS key ARN
    # (KeySigningKeyAlreadyExists), so mint a second customer managed key.
    key_arn_b = _create_dnssec_kms_key(ctx)
    ksk_b = _ksk_name(ctx, "b")
    _create_ksk(ctx, route53, zone_id, key_arn_b, ksk_b, "INACTIVE")
    dnssec = _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda r: _ksk_status(r, ksk_b) == "INACTIVE",
        timeout_s=90,
    )
    status = _ksk_status(dnssec, ksk_b)
    assert status == "INACTIVE", f"expected ksk_b INACTIVE after create, got {status!r}"

    route53.activate_key_signing_key(HostedZoneId=zone_id, Name=ksk_b)
    dnssec = _poll_until(
        lambda: route53.get_dnssec(HostedZoneId=zone_id),
        lambda r: _ksk_status(r, ksk_b) == "ACTIVE",
        timeout_s=90,
    )
    status = _ksk_status(dnssec, ksk_b)
    assert status == "ACTIVE", f"expected ksk_b ACTIVE after activating a genuinely INACTIVE KSK, got {status!r}"


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _create_dnssec_kms_key(ctx):
    # Route 53 DNSSEC requires the customer managed KMS key in us-east-1 regardless of the
    # region under test; ctx.client(region=) keeps the target's endpoint and credentials.
    kms = ctx.client("kms", region="us-east-1")
    account_id = _account_id(ctx)
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_dnssec_kms_key_policy(account_id),
        Description="sim2real route53 DNSSEC behavioral check key",
        Tags=[{"TagKey": "sim2real", "TagValue": "route53-ksk-idempotent"}],
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
    route53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=zone_id.split("/")[-1],
        AddTags=[{"Key": "sim2real", "Value": "route53-ksk-idempotent"}],
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
