"""deploy-route53-keysigningkey-inplace-update-replacement-and-dnssec-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-route53-keysigningkey-inplace-update-replacement-and-dnssec-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "route53"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=400.0):
    """Poll DescribeStacks every 2s until a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _paginate(client, op, key, **kw):
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _decisive_events(cf, stack_id):
    events = _paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
            for e in events if not e["ResourceStatus"].endswith("_IN_PROGRESS")]


def _physical_id(cf, stack_id, logical_id):
    detail = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def _already_gone(exc: ClientError, stack_ref: str) -> bool:
    err = exc.response["Error"]
    return (err.get("Code"), err.get("Message")) == (
        "ValidationError", f"Stack with id {stack_ref} does not exist")


def _delete_stack(cf, stack_ref, timeout_s=400.0):
    """Delete by name or id; safe to call on an already fully-deleted stack.

    Once a stack reaches DELETE_COMPLETE, DescribeStacks by its *name* (not its id/ARN)
    answers "does not exist" -- a deliberately deleted stack, not a missing one.
    """
    try:
        status = cf.describe_stacks(StackName=stack_ref)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if _already_gone(exc, stack_ref):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_ref)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = cf.describe_stacks(StackName=stack_ref)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _already_gone(exc, stack_ref):
                return
            raise
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_ref} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)
    assert status == "DELETE_COMPLETE", f"stack {stack_ref} delete ended {status!r}"


def _dnssec_kms_key_policy(account_id: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowRoute53DnssecSigning",
                "Effect": "Allow",
                "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"],
                "Resource": "*",
            },
            {
                "Sid": "AllowRoute53DnssecGrant",
                "Effect": "Allow",
                "Principal": {"Service": "dnssec-route53.amazonaws.com"},
                "Action": "kms:CreateGrant",
                "Resource": "*",
                "Condition": {"Bool": {"kms:GrantIsForAWSResource": True}},
            },
        ],
    })


def _create_signing_key(ctx) -> str:
    """A customer managed CMK for Route 53 DNSSEC: ECC_NIST_P256, sign/verify, in us-east-1
    (the only region Route 53 accepts a DNSSEC signing key from, regardless of the stack's own
    region).

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec-cmk-requirements.html
    """
    kms = ctx.client("kms", region="us-east-1")
    account = ctx.client("sts").get_caller_identity()["Account"]
    key = kms.create_key(
        KeySpec="ECC_NIST_P256",
        KeyUsage="SIGN_VERIFY",
        Policy=_dnssec_kms_key_policy(account),
        Description=ctx.unique_name("sim2real-r53dnssec-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key["Arn"]


def _create_public_zone(ctx) -> str:
    route53 = ctx.client("route53")
    name = f"{ctx.unique_name('sim2real-r53kskcf-')}.test."
    resp = route53.create_hosted_zone(
        Name=name, CallerReference=ctx.unique_name("sim2real-r53kskcf-cr-")
    )
    zone_id = resp["HostedZone"]["Id"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    return zone_id


def _ksk_name(ctx, suffix: str) -> str:
    raw = ctx.unique_name(f"sim2realksk{suffix}")
    return re.sub(r"[^0-9A-Za-z_]", "_", raw)[:128]


def _template(zone_id: str, ksk_name: str, status: str, key_arn: str, with_dnssec: bool) -> str:
    resources = {
        "Ksk": {
            "Type": "AWS::Route53::KeySigningKey",
            "Properties": {
                "HostedZoneId": zone_id,
                "Name": ksk_name,
                "Status": status,
                "KeyManagementServiceArn": key_arn,
            },
        },
    }
    if with_dnssec:
        resources["Dnssec"] = {
            "Type": "AWS::Route53::DNSSEC",
            "Properties": {"HostedZoneId": zone_id},
            "DependsOn": "Ksk",
        }
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _ksk_entry(dnssec_resp, name: str):
    for ksk in dnssec_resp.get("KeySigningKeys", []):
        if ksk["Name"] == name:
            return ksk
    return None


def _poll_serve_signature(route53, zone_id: str, expected: str, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = route53.get_dnssec(HostedZoneId=zone_id)
        last = resp["Status"]["ServeSignature"]
        if last == expected:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"Status.ServeSignature never reached {expected!r}, last {last!r}")


def _poll_ksk_status(route53, zone_id: str, name: str, expected: str, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = route53.get_dnssec(HostedZoneId=zone_id)
        entry = _ksk_entry(resp, name)
        if entry is not None:
            last = entry["Status"]
            if last == expected:
                return entry
        time.sleep(interval_s)
    raise AssertionError(f"KSK {name!r} never reached status {expected!r}, last seen {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Route53::KeySigningKey's Status flips in place (same physical id)
    while unsigned, is replaced (new physical id) when its Name changes, and removing its
    AWS::Route53::DNSSEC sibling turns signing off while the KSK and the zone survive.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-dnssec.html
    """
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    key_arn_1 = _create_signing_key(ctx)
    key_arn_2 = _create_signing_key(ctx)
    zone_id = _create_public_zone(ctx)
    name_1 = _ksk_name(ctx, "a")
    name_2 = _ksk_name(ctx, "b")

    stack_name = ctx.unique_name("sim2real-r53kskcf-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(zone_id, name_1, "ACTIVE", key_arn_1, with_dnssec=True),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}"
    ksk_physical_id_1 = _physical_id(cfn, stack_id, "Ksk")

    _poll_ksk_status(route53, zone_id, name_1, "ACTIVE")
    _poll_serve_signature(route53, zone_id, "SIGNING")
    entry = _ksk_entry(route53.get_dnssec(HostedZoneId=zone_id), name_1)
    assert (entry["Status"], entry["KmsArn"]) == ("ACTIVE", key_arn_1), (
        f"created KSK (Status, KmsArn) {(entry['Status'], entry['KmsArn'])!r}, "
        f"expected {('ACTIVE', key_arn_1)!r}"
    )

    # Drop the DNSSEC sibling: signing turns off, the KSK and the zone are untouched.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(zone_id, name_1, "ACTIVE", key_arn_1, with_dnssec=False),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"dnssec removal ended {status!r}: {_decisive_events(cfn, stack_id)!r}"
    _poll_serve_signature(route53, zone_id, "NOT_SIGNING")
    entry = _ksk_entry(route53.get_dnssec(HostedZoneId=zone_id), name_1)
    assert entry is not None and entry["Status"] == "ACTIVE", (
        f"KSK {name_1!r} expected to survive the DNSSEC resource's removal, got {entry!r}"
    )
    assert route53.get_hosted_zone(Id=zone_id)["HostedZone"]["Id"] == f"/hostedzone/{zone_id}", (
        "zone must survive removing the DNSSEC resource that signed it"
    )

    # In-place update: Status is the KeySigningKey resource's one mutable property.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(zone_id, name_1, "INACTIVE", key_arn_1, with_dnssec=False),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"in-place status update ended {status!r}: {_decisive_events(cfn, stack_id)!r}"
    assert _physical_id(cfn, stack_id, "Ksk") == ksk_physical_id_1, (
        "an in-place Status update must keep the KeySigningKey's physical id"
    )
    _poll_ksk_status(route53, zone_id, name_1, "INACTIVE")

    # Replacement update: Name is createOnly, so CloudFormation replaces the resource. A second
    # signing key avoids CreateKeySigningKey's own uniqueness rule on KmsArn within one zone,
    # which would otherwise collide with the still-live original resource mid-replacement.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(zone_id, name_2, "INACTIVE", key_arn_2, with_dnssec=False),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"replacement update ended {status!r}: {_decisive_events(cfn, stack_id)!r}"
    ksk_physical_id_2 = _physical_id(cfn, stack_id, "Ksk")
    assert ksk_physical_id_2 != ksk_physical_id_1, (
        "a Name change must replace the KeySigningKey, giving it a new physical id"
    )
    dnssec_after_replace = route53.get_dnssec(HostedZoneId=zone_id)
    names_after_replace = {k["Name"] for k in dnssec_after_replace["KeySigningKeys"]}
    assert names_after_replace == {name_2}, (
        f"expected only {name_2!r} after replacement, zone holds {names_after_replace!r}"
    )

    # Deleting the stack removes the KeySigningKey; the zone it signed is untouched.
    _delete_stack(cfn, stack_id)
    dnssec_after_delete = route53.get_dnssec(HostedZoneId=zone_id)
    assert dnssec_after_delete["KeySigningKeys"] == [], (
        f"expected no key-signing keys after stack delete, got {dnssec_after_delete['KeySigningKeys']!r}"
    )
    assert dnssec_after_delete["Status"]["ServeSignature"] == "NOT_SIGNING", (
        f"expected NOT_SIGNING after stack delete, got {dnssec_after_delete['Status']!r}"
    )
    assert route53.get_hosted_zone(Id=zone_id)["HostedZone"]["Id"] == f"/hostedzone/{zone_id}", (
        "the hosted zone itself must survive deleting the stack that signed it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
