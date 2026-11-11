"""delete-acme-external-account-binding-missing-idempotent-noop."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-acme-external-account-binding-missing-idempotent-noop"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAcmeExternalAccountBinding on an already-deleted binding succeeds silently as an
    idempotent no-op, and the binding stays gone."""

    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    role_arn = _create_eab_role(ctx, iam)
    binder = _binding_client(ctx, iam, sts, [role_arn])
    endpoint_arn = _create_acme_endpoint(ctx, acm)

    eab_arn = _retry_create_binding(ctx, binder, endpoint_arn, role_arn)["ExternalAccountBinding"][
        "AcmeExternalAccountBindingArn"
    ]

    # Positive control: the first delete succeeds.
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    expected_message = f"Could not find ACME external account binding {eab_arn}."
    code, message = _error_code(
        lambda: acm.describe_acme_external_account_binding(
            AcmeExternalAccountBindingArn=eab_arn
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected the binding to be gone after its first delete, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The operation's declared errors omit ResourceNotFoundException, so a repeat delete must
    # succeed silently.
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    # Effect confirmed absent afterwards: still gone, the repeat delete did not resurrect or
    # otherwise mutate anything.
    code_after, message_after = _error_code(
        lambda: acm.describe_acme_external_account_binding(
            AcmeExternalAccountBindingArn=eab_arn
        )
    )
    assert code_after == "ResourceNotFoundException", (
        f"expected the binding to remain gone after the idempotent re-delete, got {code_after!r}"
    )
    assert message_after == expected_message, f"expected message {expected_message!r}, got {message_after!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _retry_create_binding(
    ctx, acm, endpoint_arn: str, role_arn: str, timeout_s: float = 180.0, interval_s: float = 2.0
) -> dict:
    """IAM grants and a fresh role session propagate with a lag; retry past AccessDeniedException
    and UnrecognizedClientException until the binder role's session and PassRole permission are
    visible to the ACM control plane."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(AcmeEndpointArn=endpoint_arn, RoleArn=role_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "UnrecognizedClientException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateAcmeExternalAccountBinding still denied after {timeout_s}s: {last_exc}")


def _create_acme_endpoint(ctx, acm, contact: str = "NOT_REQUIRED") -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact=contact,
        CertificateAuthority={"PublicCertificateAuthority": {}},
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
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
