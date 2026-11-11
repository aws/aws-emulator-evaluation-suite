"""ksk-deactivate-last-active-key-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "ksk-deactivate-last-active-key-rejected"
GROUP = "error-semantics"
SERVICES = ["route53"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deactivating the sole ACTIVE KSK of a zone with DNSSEC signing currently enabled
    is rejected with KeySigningKeyInUse (losing it would break signing), and the KSK
    stays ACTIVE and signing stays enabled."""
    r53 = ctx.client("route53")
    zone_id, kms_arn = _dnssec_zone_and_key(ctx)
    name = _ksk_name(ctx, "lastactive")

    r53.create_key_signing_key(
        CallerReference=ctx.unique_name("cr-"),
        HostedZoneId=zone_id,
        KeyManagementServiceArn=kms_arn,
        Name=name,
        Status="ACTIVE",
    )
    ctx.on_cleanup(lambda: _best_effort_remove_ksk(ctx, zone_id, name))

    enable_resp = r53.enable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _wait_change_insync(ctx, enable_resp["ChangeInfo"]["Id"])
    ctx.on_cleanup(lambda: _best_effort(lambda: r53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)))
    _poll_dnssec_serve_signature(ctx, zone_id, "SIGNING")

    code, message = _client_error(lambda: r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name))
    assert code == "KeySigningKeyInUse", f"expected KeySigningKeyInUse, got {code!r}: {message!r}"
    expected_message = f"Key Signing Key with name '{name}' is the only available ACTIVE key for the hosted zone."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the KSK is still ACTIVE and the zone is still signing
    status = next(k["Status"] for k in r53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"] if k["Name"] == name)
    assert status == "ACTIVE", f"expected the rejected KSK to stay ACTIVE, got {status!r}"
    serve_signature = r53.get_dnssec(HostedZoneId=zone_id)["Status"]["ServeSignature"]
    assert serve_signature == "SIGNING", f"expected zone to stay SIGNING after the rejected deactivation, got {serve_signature!r}"

    # positive control: disabling signing first makes the same deactivation legal
    disable_resp = r53.disable_hosted_zone_dnssec(HostedZoneId=zone_id)
    _wait_change_insync(ctx, disable_resp["ChangeInfo"]["Id"])
    _poll_dnssec_serve_signature(ctx, zone_id, "NOT_SIGNING")
    r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
    _poll_ksk_status(ctx, zone_id, name, "INACTIVE")


def _client_error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DNSSECNotFound",
            "HostedZoneNotFound",
            "NoSuchHostedZone",
            "NoSuchKeySigningKey",
            "NotFoundException",
        ):
            raise


def _ksk_name(ctx, suffix):
    return ctx.unique_name(f"sim2real{suffix}").replace("-", "_")


def _best_effort_remove_ksk(ctx, zone_id, name):
    r53 = ctx.client("route53")
    _best_effort(lambda: r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name))
    _best_effort(lambda: r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name))


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
    regardless of the region under test, so the KMS client is pinned there."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx):
    kms = _kms_client_for_dnssec(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_kms_dnssec_policy(account_id),
        Tags=[{"TagKey": "sim2real", "TagValue": "ksk-deactivate-last-active-key-rejected"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)))
    return key["Arn"]


def _dnssec_zone_and_key(ctx):
    """(hosted_zone_id, kms_arn) for a fresh throwaway zone.

    EnableHostedZoneDNSSEC's delegation check only applies when the parent domain resolves
    publicly: a synthetic unregistered zone name has no real parent to mismatch against, so
    signing enables successfully on a freshly created zone -- no pre-delegated zone needed.
    """
    r53 = ctx.client("route53")
    zone = r53.create_hosted_zone(
        Name=ctx.unique_name("sim2real-dnssec-") + ".test.",
        CallerReference=ctx.unique_name("callerref-"),
    )["HostedZone"]
    zone_id = zone["Id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: r53.delete_hosted_zone(Id=zone_id)))
    r53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=zone_id.rsplit("/", 1)[-1],
        AddTags=[{"Key": "sim2real", "Value": "ksk-deactivate-last-active-key-rejected"}],
    )
    return zone_id, _create_dnssec_kms_key(ctx)


def _wait_change_insync(ctx, change_id, timeout_s=120.0, interval_s=3.0):
    r53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if last == "INSYNC":
            return
        time.sleep(interval_s)
    raise AssertionError(f"change {change_id} never reached INSYNC (last saw {last})")


def _poll_dnssec_serve_signature(ctx, zone_id, expected, timeout_s=150.0, interval_s=3.0):
    r53 = ctx.client("route53")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53.get_dnssec(HostedZoneId=zone_id)["Status"]["ServeSignature"]
        if last == expected:
            return
        time.sleep(interval_s)
    raise AssertionError(f"DNSSEC ServeSignature never reached {expected} (last saw {last})")


def _poll_ksk_status(ctx, zone_id, name, expected_status, timeout_s=90.0, interval_s=3.0):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
