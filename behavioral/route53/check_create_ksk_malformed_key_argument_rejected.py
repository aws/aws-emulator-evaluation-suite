"""create-ksk-malformed-key-argument-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-ksk-malformed-key-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKeySigningKey rejects a permissioned RSA_2048 KMS key (DNSSEC requires ECC_NIST_P256)
    with InvalidKMSArn and persists no KSK, while an ECC_NIST_P256 key succeeds on the same zone."""
    route53 = ctx.client("route53")
    kms = _kms_client_us_east_1(ctx)
    sts = ctx.client("sts")

    zone_name = f"{ctx.unique_name('sim2real-kskbad-')}.test"
    created_zone = route53.create_hosted_zone(Name=zone_name, CallerReference=str(uuid.uuid4()))
    zone_id = created_zone["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    _wait_for_change_insync(route53, created_zone["ChangeInfo"]["Id"])

    wrong_key_arn = _create_dnssec_kms_key(ctx, kms, sts, key_spec="RSA_2048")
    bad_name = ctx.unique_name("sim2real_kskbad_").replace("-", "_")

    code, message = _error(
        lambda: route53.create_key_signing_key(
            CallerReference=str(uuid.uuid4()),
            HostedZoneId=zone_id,
            KeyManagementServiceArn=wrong_key_arn,
            Name=bad_name,
            Status="INACTIVE",
        )
    )
    assert code == "InvalidKMSArn", f"expected InvalidKMSArn, got {code}"
    expected = (
        f"The customer managed key with ARN '{wrong_key_arn}' could not be used by Route 53 "
        "DNSSEC. Check to make sure that the customer managed key has not been deleted. "
        "Otherwise, review its configurations and key policy, to make sure it is in compliance "
        "with Route 53 DNSSEC requirements."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # No KSK must have been persisted under that name.
    names_after_rejection = {k["Name"] for k in route53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]}
    assert bad_name not in names_after_rejection, (
        f"expected no KSK named {bad_name!r} after rejection, found it in {names_after_rejection}"
    )

    # Positive control: a correctly-specced key on the same hosted zone succeeds.
    good_key_arn = _create_dnssec_kms_key(ctx, kms, sts, key_spec="ECC_NIST_P256")
    good_name = ctx.unique_name("sim2real_kskgood_").replace("-", "_")
    resp = route53.create_key_signing_key(
        CallerReference=str(uuid.uuid4()),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=good_key_arn,
        Name=good_name,
        Status="INACTIVE",
    )
    ctx.on_cleanup(lambda: route53.delete_key_signing_key(HostedZoneId=zone_id, Name=good_name))
    assert resp["KeySigningKey"]["Name"] == good_name, (
        f"expected created KSK name {good_name!r}, got {resp['KeySigningKey']['Name']!r}"
    )
    assert resp["KeySigningKey"]["Status"] == "INACTIVE", (
        f"expected created KSK status 'INACTIVE', got {resp['KeySigningKey']['Status']!r}"
    )

    # Terminal read: independent of the mutating create call, at the destination.
    keys_after_success = {
        k["Name"]: k["Status"] for k in route53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]
    }
    assert keys_after_success.get(good_name) == "INACTIVE", (
        f"expected get_dnssec to list {good_name!r} as 'INACTIVE', got {keys_after_success}"
    )
    assert bad_name not in keys_after_success, (
        f"expected {bad_name!r} to remain absent after the positive control, found it in {keys_after_success}"
    )


def _kms_client_us_east_1(ctx):
    """Route 53 DNSSEC requires the customer managed KMS key (and the
    CreateKeySigningKey call itself) to target us-east-1 regardless of the
    region under test."""
    return ctx.client("kms", region="us-east-1")


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _wait_for_change_insync(route53, change_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC within {timeout_s}s")


def _dnssec_key_policy(account_id):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowRoute53DNSSECService",
                    "Effect": "Allow",
                    "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                    "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign", "kms:Verify"],
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
    )


def _create_dnssec_kms_key(ctx, kms, sts, key_spec):
    account_id = sts.get_caller_identity()["Account"]
    created = kms.create_key(
        KeySpec=key_spec,
        KeyUsage="SIGN_VERIFY",
        Policy=_dnssec_key_policy(account_id),
        Tags=[{"TagKey": "sim2real-check", "TagValue": ctx.unique_name("ksk-malformed-")}],
    )
    key_id = created["KeyMetadata"]["KeyId"]
    key_arn = created["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    _wait_for_key_enabled(kms, key_id)
    return key_arn


def _wait_for_key_enabled(kms, key_id, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"] == "Enabled":
            return
        time.sleep(interval_s)
    raise AssertionError(f"KMS key {key_id} never reached Enabled within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
