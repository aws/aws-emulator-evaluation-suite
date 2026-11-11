"""get-eab-credentials-cross-account-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-eab-credentials-cross-account-denied"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAcmeExternalAccountBindingCredentials denies a caller with no IAM policies with an
    AccessDeniedException naming its session, while the binding's owner can still read them.
    """

    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    role_arn = _create_eab_role(ctx, iam)
    binder = _binding_client(ctx, iam, sts, [role_arn])
    endpoint_arn = _create_acme_endpoint(ctx, acm)
    eab_arn = _create_binding_with_retry(ctx, binder, endpoint_arn, role_arn)[
        "ExternalAccountBinding"
    ]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )

    account_id = sts.get_caller_identity()["Account"]
    assume_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    restricted_role_name = ctx.unique_name("sim2real-acme-noperm-role-")
    restricted_role_arn = iam.create_role(
        RoleName=restricted_role_name,
        AssumeRolePolicyDocument=json.dumps(assume_trust),
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=restricted_role_name))

    # The role has no identity-based policies at all, so any AWS action it attempts is an
    # implicit deny -- this is the permission-boundary condition under test.
    creds = _assume_role_with_retry(sts, restricted_role_arn, timeout_s=30, interval_s=3)

    restricted_acm = ctx.client(
        "acm",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # A just-assumed session can answer UnrecognizedClientException until it propagates; retry only that.
    deadline = time.monotonic() + 60.0
    while True:
        code, message = _error(
            lambda: restricted_acm.get_acme_external_account_binding_credentials(
                AcmeExternalAccountBindingArn=eab_arn
            )
        )
        if code != "UnrecognizedClientException" or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    # A caller with zero identity-based policies is refused by an implicit deny.
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no acm permissions, got {code!r}"
    )
    action = "acm:GetAcmeExternalAccountBindingCredentials"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{restricted_role_name}/sim2real-noperm "
        f"is not authorized to perform: {action} on resource: {eab_arn} "
        f"because no identity-based policy allows the {action} action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the binding's actual owner (full permissions) can still retrieve
    # the real credentials -- the resource itself is intact, only the unauthorized caller
    # was rejected.
    owner_creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    assert owner_creds["KeyId"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_acme_endpoint(ctx, acm, contact: str = "NOT_REQUIRED") -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact=contact,
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _create_eab_role(ctx, iam) -> str:
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
    name = ctx.unique_name("sim2real-acme-eab-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_binding_with_retry(
    ctx, acm, endpoint_arn: str, role_arn: str, timeout_s: float = 180.0, interval_s: float = 2.0
) -> dict:
    """Retries CreateAcmeExternalAccountBinding on AccessDeniedException and
    UnrecognizedClientException while the binder role's iam:PassRole grant and session propagate."""
    deadline = time.monotonic() + min(timeout_s, ctx.time_left() or timeout_s)
    last_error: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
            )
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateAcmeExternalAccountBinding still denied after {timeout_s}s: {last_error}"
    )


def _binding_client(ctx, iam, sts, role_arns):
    # CreateAcmeExternalAccountBinding needs iam:PassRole on each binding role; a role the check
    # creates holds only that grant and the create call, so the calling identity's own policies
    # stay untouched.
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
            {"Effect": "Allow", "Action": "acm:CreateAcmeExternalAccountBinding", "Resource": "*"},
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


def _assume_role_with_retry(sts, role_arn: str, timeout_s: float = 30.0, interval_s: float = 3.0):
    """Retries assume-role to absorb IAM eventual-consistency propagation lag after create_role."""
    deadline = time.monotonic() + timeout_s
    last_error: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-noperm")[
                "Credentials"
            ]
        except ClientError as e:
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(
        f"could not assume the freshly created role within {timeout_s}s: {last_error}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
