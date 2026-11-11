"""ksk-public-key-material-round-trip."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "ksk-public-key-material-round-trip"
GROUP = "representation"
SERVICES = ["route53"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A KSK's public key and DS record material are byte-identical across repeated GetDNSSEC
    reads, since they derive deterministically from the KMS public key."""
    route53 = ctx.client("route53")
    # DNSSEC customer managed keys must live in us-east-1 regardless of the client's
    # default region (https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/
    # dns-configuring-dnssec-cmk-requirements.html); Route 53 itself is a global
    # control plane and needs no pin.
    kms = ctx.client("kms", region="us-east-1")
    sts = ctx.client("sts")

    key_arn = _create_dnssec_kms_key(ctx, kms, sts, key_spec="ECC_NIST_P256")

    zone_name = f"{ctx.unique_name('sim2real-ksk-')}.test"
    created = route53.create_hosted_zone(Name=zone_name, CallerReference=str(uuid.uuid4()))
    zone_id = created["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    _wait_for_change_insync(route53, created["ChangeInfo"]["Id"])

    ksk_name = ctx.unique_name("sim2real_ksk_").replace("-", "_")
    resp = route53.create_key_signing_key(
        CallerReference=str(uuid.uuid4()),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=key_arn,
        Name=ksk_name,
        Status="INACTIVE",
    )
    ctx.on_cleanup(lambda: route53.delete_key_signing_key(HostedZoneId=zone_id, Name=ksk_name))
    created_ksk = resp["KeySigningKey"]
    assert created_ksk["DSRecord"], "CreateKeySigningKey returned an empty DSRecord"
    assert created_ksk["DNSKEYRecord"], "CreateKeySigningKey returned an empty DNSKEYRecord"

    read_1 = _get_ksk(route53, zone_id, ksk_name)
    read_2 = _get_ksk(route53, zone_id, ksk_name)

    for field in ("DSRecord", "DNSKEYRecord", "DigestValue", "PublicKey", "KeyTag", "KmsArn"):
        assert read_1[field] == read_2[field], f"{field} not stable across GetDNSSEC reads"
        assert read_1[field] == created_ksk[field], f"{field} drifted from CreateKeySigningKey response"
    assert read_1["KmsArn"] == key_arn, f"GetDNSSEC KmsArn {read_1['KmsArn']!r} != backing key {key_arn!r}"


def _wait_for_change_insync(route53, change_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = route53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC within {timeout_s}s")


def _get_ksk(route53, zone_id, name):
    dnssec = route53.get_dnssec(HostedZoneId=zone_id)
    for ksk in dnssec["KeySigningKeys"]:
        if ksk["Name"] == name:
            return ksk
    raise AssertionError(f"KSK {name} not found in GetDNSSEC response")


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
        Tags=[{"TagKey": "sim2real-check", "TagValue": ctx.unique_name("ksk-material-")}],
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
