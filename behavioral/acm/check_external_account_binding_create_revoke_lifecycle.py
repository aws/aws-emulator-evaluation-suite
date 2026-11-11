"""external-account-binding-create-revoke-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "external-account-binding-create-revoke-lifecycle"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created external account binding is describable then transitions to revoked
    (not silently deleted) after RevokeAcmeExternalAccountBinding."""

    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_acme_eab_role(ctx, iam)
    binder = _binding_client(ctx, iam, sts, [role_arn])

    eab = _create_binding_with_retry(
        ctx, binder,
        endpoint_arn,
        role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))
    )
    assert eab["RoleArn"] == role_arn, f"expected RoleArn {role_arn!r}, got {eab['RoleArn']!r}"
    assert eab.get("RevokedAt") is None, f"expected no RevokedAt on a freshly created binding, got {eab.get('RevokedAt')!r}"

    described = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert described["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"expected arn {eab_arn!r}, got {described['AcmeExternalAccountBindingArn']!r}"
    )
    assert described["RoleArn"] == role_arn, f"expected RoleArn {role_arn!r}, got {described['RoleArn']!r}"
    assert described.get("RevokedAt") is None, f"binding shows revoked before it was revoked: {described}"

    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    revoked = _poll_until(
        lambda: acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
            "ExternalAccountBinding"
        ],
        lambda b: b.get("RevokedAt") is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    # Revoking transitions the binding's state; it must remain a describable resource
    # (not deleted) with the same identity and role association.
    assert revoked["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"expected arn {eab_arn!r} to still describe after revoke, got {revoked['AcmeExternalAccountBindingArn']!r}"
    )
    assert revoked["RoleArn"] == role_arn, f"expected RoleArn {role_arn!r} preserved after revoke, got {revoked['RoleArn']!r}"
    assert revoked["RevokedAt"] is not None, "expected RevokedAt to be set after RevokeAcmeExternalAccountBinding"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _role_visible(iam, name) -> bool:
    try:
        iam.get_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise
    return True


def _create_active_endpoint(ctx, acm):
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    return arn


def _create_acme_eab_role(ctx, iam):
    name = ctx.unique_name("sim2real-acme-eab-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=name)))
    _poll_until(lambda: _role_visible(iam, name), lambda visible: visible, timeout_s=20.0, interval_s=1.0)
    return role_arn


def _binding_client(ctx, iam, sts, role_arns):
    # CreateAcmeExternalAccountBinding (with Tags) needs iam:PassRole on each binding role; a role
    # the check creates holds only those grants, so the calling identity's own policies stay
    # untouched.
    identity = sts.get_caller_identity()
    name = ctx.unique_name("sim2real-acme-eab-binder-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{identity['Account']}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:userid": identity["UserId"]}},
            }
        ],
    }
    binder_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": list(role_arns),
            },
            {"Effect": "Allow", "Action": ["acm:CreateAcmeExternalAccountBinding", "acm:TagResource"], "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=name, PolicyName="acme-eab-binder", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="acme-eab-binder"))
    # A new role's trust policy propagates with a lag; retry only the documented denial.
    deadline = time.monotonic() + min(60.0, ctx.time_left() or 60.0)
    while True:
        try:
            creds = sts.assume_role(RoleArn=binder_arn, RoleSessionName="acme-eab-binder")["Credentials"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
    return ctx.client(
        "acm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _create_binding_with_retry(ctx, acm, endpoint_arn, role_arn, timeout_s=180.0, interval_s=2.0, **kwargs):
    # The binder role's PassRole grant and its fresh session propagate with a lag; retry only the
    # two answers AWS gives in that window (AccessDeniedException, UnrecognizedClientException).
    deadline = time.monotonic() + min(timeout_s, ctx.time_left() or timeout_s)
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn, **kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateAcmeExternalAccountBinding still denied after {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
