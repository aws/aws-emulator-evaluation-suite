"""list-external-account-bindings-reflects-created."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-external-account-bindings-reflects-created"
GROUP = "state-machine"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created external account binding appears in ListAcmeExternalAccountBindings."""

    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_acme_eab_role(ctx, iam)
    binder = _binding_client(ctx, iam, sts, [role_arn])

    eab_arn = _create_binding_with_retry(
        ctx, binder,
        endpoint_arn,
        role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))
    )

    found = _find_in_list(acm, endpoint_arn, eab_arn)
    assert found is not None, f"created binding {eab_arn} did not appear in ListAcmeExternalAccountBindings"
    assert found["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"expected arn {eab_arn!r}, got {found['AcmeExternalAccountBindingArn']!r}"
    )
    assert found["AcmeEndpointArn"] == endpoint_arn, (
        f"expected endpoint arn {endpoint_arn!r}, got {found['AcmeEndpointArn']!r}"
    )
    assert found["RoleArn"] == role_arn, f"expected RoleArn {role_arn!r}, got {found['RoleArn']!r}"


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
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _role_visible(iam, name):
    try:
        iam.get_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return False
    return True


def _create_active_endpoint(ctx, acm):
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"endpoint {arn} entered {status} instead of ACTIVE")
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


def _find_in_list(acm, endpoint_arn, eab_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        next_token = None
        while True:
            kwargs = {"AcmeEndpointArn": endpoint_arn, "MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            page = acm.list_acme_external_account_bindings(**kwargs)
            for binding in page.get("ExternalAccountBindings", []):
                if binding["AcmeExternalAccountBindingArn"] == eab_arn:
                    return binding
            next_token = page.get("NextToken")
            if not next_token:
                break
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
