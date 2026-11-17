"""deploy-route53-keysigningkey-wrong-kms-key-spec-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-route53-keysigningkey-wrong-kms-key-spec-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "route53"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
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


def _failed_reason(cf, stack_id, logical_id):
    events = _paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(rows) == 1, f"expected one CREATE_FAILED row for {logical_id}, got {rows!r}"
    return rows[0]


def _masked(text: str, *values: str) -> str:
    """``text`` with its dynamic request id, SDK attempt count and the run's own ARN stripped."""
    text = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    for value in sorted(values, key=len, reverse=True):
        text = text.replace(value, "<arn>")
    return text


def _handler_reason(reason: str, *mask_values: str):
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"], *mask_values), m["code"]


def _already_gone(exc: ClientError, stack_ref: str) -> bool:
    err = exc.response["Error"]
    return (err.get("Code"), err.get("Message")) == (
        "ValidationError", f"Stack with id {stack_ref} does not exist")


def _delete_stack(cf, stack_ref, timeout_s=300.0):
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


def _kms_key_policy(account_id: str) -> str:
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


def _create_signing_key(ctx, key_spec: str) -> str:
    """A customer managed CMK for Route 53 DNSSEC, in us-east-1 regardless of the stack's own
    region: ``key_spec`` ECC_NIST_P256 is the only spec DNSSEC signing accepts.
    """
    kms = ctx.client("kms", region="us-east-1")
    account = ctx.client("sts").get_caller_identity()["Account"]
    key = kms.create_key(
        KeySpec=key_spec,
        KeyUsage="SIGN_VERIFY",
        Policy=_kms_key_policy(account),
        Description=ctx.unique_name("sim2real-r53dnssecneg-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key["Arn"]


def _create_public_zone(ctx) -> str:
    route53 = ctx.client("route53")
    name = f"{ctx.unique_name('sim2real-r53kskneg-')}.test."
    resp = route53.create_hosted_zone(
        Name=name, CallerReference=ctx.unique_name("sim2real-r53kskneg-cr-")
    )
    zone_id = resp["HostedZone"]["Id"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))
    return zone_id


def _ksk_name(ctx, suffix: str) -> str:
    raw = ctx.unique_name(f"sim2realksk{suffix}")
    return re.sub(r"[^0-9A-Za-z_]", "_", raw)[:128]


def _template(zone_id: str, ksk_name: str, key_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Ksk": {
                "Type": "AWS::Route53::KeySigningKey",
                "Properties": {
                    "HostedZoneId": zone_id,
                    "Name": ksk_name,
                    "Status": "ACTIVE",
                    "KeyManagementServiceArn": key_arn,
                },
            },
        },
        "Outputs": {"KskName": {"Value": ksk_name}},
    })


def _ksk_names(route53, zone_id: str) -> set:
    return {k["Name"] for k in route53.get_dnssec(HostedZoneId=zone_id)["KeySigningKeys"]}


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Route53::KeySigningKey referencing an RSA_2048 KMS key (DNSSEC
    requires ECC_NIST_P256) rolls back with Route 53's own InvalidRequest reason and creates no
    key-signing key, while the same template pointed at an ECC_NIST_P256 key deploys cleanly.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html
    """
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    zone_id = _create_public_zone(ctx)

    wrong_key_arn = _create_signing_key(ctx, "RSA_2048")
    bad_name = _ksk_name(ctx, "bad")
    bad_stack_name = ctx.unique_name("sim2real-r53kskneg-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack_name))
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=_template(zone_id, bad_name, wrong_key_arn),
        Tags=[{"Key": "sim2real", "Value": bad_stack_name}],
    )["StackId"]
    status = _wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"stack with a mis-specced key ended {status!r}"

    message, handler_code = _handler_reason(
        _failed_reason(cfn, bad_stack_id, "Ksk"), wrong_key_arn
    )
    expected_message = (
        "The customer managed key with ARN '<arn>' could not be used by Route 53 "
        "DNSSEC. Check to make sure that the customer managed key has not been deleted. "
        "Otherwise, review its configurations and key policy, to make sure it is in compliance "
        "with Route 53 DNSSEC requirements. (Service: Route53, Status Code: 400, Request ID: "
        "<id>) (SDK Attempt Count: <n>)"
    )
    assert (message, handler_code) == (expected_message, "InvalidRequest"), (
        f"handler reason {(message, handler_code)!r}, expected {(expected_message, 'InvalidRequest')!r}"
    )
    assert bad_name not in _ksk_names(route53, zone_id), (
        f"expected no key-signing key named {bad_name!r} after rollback, zone holds "
        f"{_ksk_names(route53, zone_id)!r}"
    )

    # Positive control: the same template, pointed at a correctly-specced key, deploys cleanly.
    good_key_arn = _create_signing_key(ctx, "ECC_NIST_P256")
    good_name = _ksk_name(ctx, "good")
    good_stack_name = ctx.unique_name("sim2real-r53kskpos-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack_name))
    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=_template(zone_id, good_name, good_key_arn),
        Tags=[{"Key": "sim2real", "Value": good_stack_name}],
    )["StackId"]
    status = _wait_stack(cfn, good_stack_id)
    assert status == "CREATE_COMPLETE", f"control stack with a well-specced key ended {status!r}"
    assert _ksk_names(route53, zone_id) == {good_name}, (
        f"expected only {good_name!r} on the zone, found {_ksk_names(route53, zone_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
