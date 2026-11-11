"""dnssec-status-unsigned-zone."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "dnssec-status-unsigned-zone"
GROUP = 'hosted-zone'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


def _list_all_record_sets(r53, zone_id):
    out = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _empty_and_delete_zone(r53, zone_id):
    try:
        for rrs in _list_all_record_sets(r53, zone_id):
            if rrs["Type"] in ("NS", "SOA"):
                continue
            try:
                r53.change_resource_record_sets(
                    HostedZoneId=zone_id,
                    ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "HostedZoneNotFound",
                    "NoSuchHealthCheck",
                    "NoSuchHostedZone",
                ):
                    raise
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise


def _create_zone(ctx, r53, *, name=None, comment=None):
    kwargs = {
        "Name": name or _zone_name(ctx),
        "CallerReference": _caller_reference(),
        "HostedZoneConfig": {"Comment": comment or "behavioral-check", "PrivateZone": False},
    }
    resp = r53.create_hosted_zone(**kwargs)
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return resp


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_change_insync(r53, change_id, timeout_s=120.0):
    _poll_until(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda s: s == "INSYNC",
        timeout_s=timeout_s,
        interval_s=3.0,
    )


def _poll_dnssec_status(r53, zone_id, target, timeout_s=240.0):
    return _poll_until(
        lambda: r53.get_dnssec(HostedZoneId=zone_id),
        lambda d: d["Status"]["ServeSignature"] == target,
        timeout_s=timeout_s,
        interval_s=10.0,
    )


def _kms_client_us_east_1(ctx):
    """Route 53 DNSSEC requires the customer managed KMS key to live in us-east-1,
    regardless of the region under test."""
    return ctx.client("kms", region="us-east-1")


def _create_dnssec_kms_key(ctx):
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
    return resp["KeyMetadata"]["Arn"]


def _create_ksk_with_retry(r53, ctx, zone_id, kms_arn, name, status, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return r53.create_key_signing_key(
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


def _deactivate_and_delete_ksk(r53, zone_id, name):
    try:
        deactivate = r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=name)
        _poll_change_insync(r53, deactivate["ChangeInfo"]["Id"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchChange",
            "NoSuchHostedZone",
            "NoSuchKeySigningKey",
        ):
            raise
    try:
        r53.delete_key_signing_key(HostedZoneId=zone_id, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHostedZone",
            "NoSuchKeySigningKey",
        ):
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh zone is NOT_SIGNING with no KSKs, and enabling DNSSEC without an ACTIVE KSK fails
    with KeySigningKeyWithActiveStatusNotFound, status unchanged; the same call then succeeds
    once an ACTIVE KSK exists."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-dnssec"))
    zone_id = resp["HostedZone"]["Id"]
    bare_id = zone_id.split("/")[-1]
    _poll_change_insync(r53, resp["ChangeInfo"]["Id"])

    dnssec = r53.get_dnssec(HostedZoneId=bare_id)
    assert "Status" in dnssec, dnssec
    serve = dnssec["Status"].get("ServeSignature")
    assert serve == "NOT_SIGNING", f"expected ServeSignature NOT_SIGNING on a fresh zone, got {serve}"
    assert dnssec.get("KeySigningKeys", []) == [], dnssec.get("KeySigningKeys")

    # break: no key signing key exists yet, so signing cannot be turned on.
    code, message = _error(lambda: r53.enable_hosted_zone_dnssec(HostedZoneId=bare_id))
    assert code == "KeySigningKeyWithActiveStatusNotFound", (
        f"expected KeySigningKeyWithActiveStatusNotFound, got {code}"
    )
    expected = (
        f"Hosted zone with ID '{bare_id.split('/')[-1]}' does not have a Key Signing Key in "
        "ACTIVE status."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: status must be unchanged by the failed enable
    after = r53.get_dnssec(HostedZoneId=bare_id)
    assert after["Status"].get("ServeSignature") == "NOT_SIGNING", after["Status"]

    # restore: give the zone a real, ACTIVE key signing key.
    kms_arn = _create_dnssec_kms_key(ctx)
    ksk_name = ctx.unique_name("ksk").replace("-", "_")
    ksk = _create_ksk_with_retry(r53, ctx, bare_id, kms_arn, ksk_name, "ACTIVE")
    ctx.on_cleanup(lambda: _deactivate_and_delete_ksk(r53, bare_id, ksk_name))
    _poll_change_insync(r53, ksk["ChangeInfo"]["Id"])

    # the identical call now succeeds.
    enable = r53.enable_hosted_zone_dnssec(HostedZoneId=bare_id)
    ctx.on_cleanup(lambda: _error_code_ignored(lambda: r53.disable_hosted_zone_dnssec(HostedZoneId=bare_id)))
    _poll_change_insync(r53, enable["ChangeInfo"]["Id"])
    signing = _poll_dnssec_status(r53, bare_id, "SIGNING")
    assert signing["Status"].get("ServeSignature") == "SIGNING", signing["Status"]


def _error_code_ignored(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DNSSECNotFound",
            "HostedZoneNotFound",
            "NoSuchHostedZone",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
