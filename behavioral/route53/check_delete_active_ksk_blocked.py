"""delete-active-ksk-blocked."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-active-ksk-blocked"
GROUP = "overly-permissive"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteKeySigningKey on a currently ACTIVE key is rejected with
    InvalidKeySigningKeyStatus rather than silently discarding signing material -- the
    KSK must be deactivated first."""
    r53 = ctx.client("route53")
    zone_id = _create_plain_zone(ctx)
    kms_arn = _create_dnssec_kms_key(ctx)
    name = _ksk_name(ctx, "activedelete")

    r53.create_key_signing_key(
        CallerReference=ctx.unique_name("cr-"),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=kms_arn,
        Name=name,
        Status="ACTIVE",
    )
    ctx.on_cleanup(lambda: _remove_ksk(ctx, zone_id, name))

    code, message = _error(lambda: r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name))
    assert code == "InvalidKeySigningKeyStatus", f"expected InvalidKeySigningKeyStatus, got {code!r}"
    expected = (
        f"Key Signing Key with name {name} cannot be deleted because current status is not "
        "INACTIVE. You can use DeactivateKeySigningKey to deactivate the Key Signing Key before "
        "you delete it."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the KSK still exists and is still ACTIVE -- nothing was deleted
    ksks = r53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]
    match = next((k for k in ksks if k["Name"] == name), None)
    assert match is not None, f"KSK {name} vanished despite the rejected delete"
    assert match["Status"] == "ACTIVE", f"expected KSK {name} still ACTIVE, got {match['Status']!r}"

    # positive control: deactivating first makes deletion legal
    r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
    _poll_ksk_status(ctx, zone_id, name, "INACTIVE")
    r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name)
    _poll_ksk_absent(ctx, zone_id, name)

    # the id is now dead: the same delete call fails not-found, it does not re-succeed
    dead_code, dead_message = _error(lambda: r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name))
    assert dead_code == "NoSuchKeySigningKey", f"expected NoSuchKeySigningKey, got {dead_code!r}"
    expected = f"The Key Signing Key with name '{name}', could not be found."
    assert dead_message == expected, f"expected message {expected!r}, got {dead_message!r}"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _best_effort(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError:
        pass


def _unless_gone(fn, *gone):
    """Teardown call: return on the listed not-found codes, raise every other failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in gone:
            raise


def _ksk_name(ctx, suffix):
    return ctx.unique_name(f"sim2real{suffix}").replace("-", "_")


def _remove_ksk(ctx, zone_id, name):
    """Deactivate then delete the KSK; an already-deleted key is the normal outcome."""
    from botocore.exceptions import ClientError

    r53 = ctx.client("route53")
    try:
        r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code == "NoSuchKeySigningKey":
            return
        if code != "InvalidKeySigningKeyStatus":
            raise
    _poll_ksk_status(ctx, zone_id, name, "INACTIVE", timeout_s=60.0, interval_s=2.0)
    _unless_gone(lambda: r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name), "NoSuchKeySigningKey")


def _create_plain_zone(ctx):
    r53 = ctx.client("route53")
    zone = r53.create_hosted_zone(
        Name=ctx.unique_name("sim2real-r53-") + ".test.",
        CallerReference=ctx.unique_name("callerref-"),
    )["HostedZone"]
    zone_id = zone["Id"].split("/")[-1]
    ctx.on_cleanup(lambda: _unless_gone(lambda: r53.delete_hosted_zone(Id=zone_id), "NoSuchHostedZone"))
    _best_effort(
        lambda: r53.change_tags_for_resource(
            ResourceType="hostedzone",
            ResourceId=zone_id,
            AddTags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-r53-ksk-delete")}],
        )
    )
    return zone_id


def _kms_dnssec_policy(account_id):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Id": "sim2real-dnssec-key-policy",
            "Statement": [
                {
                    "Sid": "EnableRootAccountPermissions",
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


def _kms_client_for_dnssec(ctx):
    """Route 53 DNSSEC only accepts customer managed KMS keys created in us-east-1,
    regardless of which region the hosted zone or the check's default client target."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx):
    kms = _kms_client_for_dnssec(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_kms_dnssec_policy(account_id),
        Tags=[{"TagKey": "Name", "TagValue": ctx.unique_name("sim2real-r53-ksk-delete")}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7), "NotFoundException"))
    return key["Arn"]


def _poll_ksk_status(ctx, zone_id, name, expected_status, timeout_s=90.0, interval_s=3.0):
    import time

    r53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        ksks = r53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]
        match = next((k for k in ksks if k["Name"] == name), None)
        last = match["Status"] if match else "<absent>"
        if last == expected_status:
            return
        time.sleep(interval_s)
    raise AssertionError(f"KSK {name} never reached status {expected_status} (last saw {last})")


def _poll_ksk_absent(ctx, zone_id, name, timeout_s=90.0, interval_s=3.0):
    import time

    r53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ksks = r53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]
        if not any(k["Name"] == name for k in ksks):
            return
        time.sleep(interval_s)
    raise AssertionError(f"KSK {name} was never removed from GetDNSSEC")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
