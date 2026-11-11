"""disable-dnssec-not-enabled-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disable-dnssec-not-enabled-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableHostedZoneDNSSEC on a zone with no DNSSEC resources returns DNSSECNotFound.

    GetDNSSEC stays NOT_SIGNING with no keys; creating a KSK on the same zone then succeeds.
    """
    r53 = ctx.client("route53")
    zone_id = _create_plain_zone(ctx)

    before = r53.get_dnssec(HostedZoneId=zone_id)
    assert before["Status"]["ServeSignature"] == "NOT_SIGNING", (
        f"expected a fresh zone to report NOT_SIGNING, got {before['Status']['ServeSignature']!r}"
    )
    assert before["KeySigningKeys"] == [], (
        f"expected a fresh zone to have no key-signing keys, got {before['KeySigningKeys']!r}"
    )

    code, message = _error(lambda: r53.disable_hosted_zone_dnssec(HostedZoneId=zone_id))
    assert code == "DNSSECNotFound", f"expected DNSSECNotFound, got {code!r}"
    expected = f"Couldn't find DNSSEC information for Hosted Zone with Id '{zone_id.split('/')[-1]}'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: zone DNSSEC state is unchanged by the rejected call
    after = r53.get_dnssec(HostedZoneId=zone_id)
    assert after["Status"]["ServeSignature"] == "NOT_SIGNING", (
        f"expected NOT_SIGNING to persist after the rejected call, got {after['Status']['ServeSignature']!r}"
    )
    assert after["KeySigningKeys"] == [], (
        f"expected no key-signing keys after the rejected call, got {after['KeySigningKeys']!r}"
    )

    # Positive control: a KSK created on this zone succeeds, so the rejection above is
    # specific to "no signing config" rather than a blanket DNSSEC failure.
    key_arn = _create_dnssec_kms_key(ctx)
    ksk_name = _ksk_name(ctx)
    _create_ksk(ctx, r53, zone_id, key_arn, ksk_name)
    control = _poll_until(
        lambda: r53.get_dnssec(HostedZoneId=zone_id),
        lambda resp: _ksk_status(resp, ksk_name) == "INACTIVE",
        timeout_s=120,
    )
    assert _ksk_status(control, ksk_name) == "INACTIVE", (
        f"expected control key-signing key {ksk_name!r} to reach INACTIVE, "
        f"last seen {control.get('KeySigningKeys')!r}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _best_effort(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHostedZone",
            "NoSuchKeySigningKey",
            "NotFoundException",
        ):
            raise


def _create_plain_zone(ctx):
    r53 = ctx.client("route53")
    zone = r53.create_hosted_zone(
        Name=ctx.unique_name("sim2real-r53-") + ".test.",
        CallerReference=ctx.unique_name("callerref-"),
    )["HostedZone"]
    zone_id = zone["Id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: r53.delete_hosted_zone(Id=zone_id)))
    return zone_id


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
    """Route 53 DNSSEC requires the customer managed KMS key to live in us-east-1,
    regardless of the region under test."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx) -> str:
    kms = _dnssec_kms_client(ctx)
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_dnssec_kms_key_policy(_account_id(ctx)),
        Description="sim2real-behav route53 dnssec control key",
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    )
    return key["Arn"]


def _ksk_name(ctx) -> str:
    raw = ctx.unique_name("ksk-ctrl-")
    return re.sub(r"[^0-9A-Za-z_]", "_", raw)[:128]


def _ksk_status(dnssec_resp, name):
    for ksk in dnssec_resp.get("KeySigningKeys", []):
        if ksk["Name"] == name:
            return ksk["Status"]
    return None


def _create_ksk(ctx, r53, zone_id, key_arn, name, timeout_s=120.0, interval_s=5.0):
    """CreateKeySigningKey can transiently fail with InvalidKMSArn while the
    freshly-created KMS key policy is still propagating; retry through that."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    from botocore.exceptions import ClientError

    while time.monotonic() < deadline:
        try:
            resp = r53.create_key_signing_key(
                CallerReference=ctx.unique_name("ksk-cr-"),
                HostedZoneId=zone_id,
                KeyManagementServiceArn=key_arn,
                Name=name,
                Status="INACTIVE",
            )
            ctx.on_cleanup(
                lambda: _best_effort(
                    lambda: r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name)
                )
            )
            return resp
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code != "InvalidKMSArn":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"CreateKeySigningKey never succeeded (KMS policy propagation?): {last_err}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
