"""get-acme-external-account-binding-credentials-cross-account-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-acme-external-account-binding-credentials-cross-account-denied"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A binding ARN with a foreign account segment is rejected with ValidationException instead of
    returning credentials, and the real binding's credentials stay retrievable and unchanged."""
    acm = ctx.client("acm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx, iam, "primary")
    binder = _binding_client(ctx, iam, sts, [role_arn])

    binding = _retry_create_binding(ctx, binder, endpoint_arn, role_arn)["ExternalAccountBinding"]
    eab_arn = binding["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
        )
    )

    baseline = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    assert baseline["KeyId"], f"expected a non-empty KeyId for the real binding, got {baseline!r}"
    assert baseline["MacKey"], f"expected a non-empty MacKey for the real binding, got {baseline!r}"

    own_account = sts.get_caller_identity()["Account"]
    foreign_arn = _swap_account(eab_arn, _foreign_account_id(own_account))

    code, message = _error(
        lambda: acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=foreign_arn)
    )
    # AWS rejects a cross-account ARN at input validation, not with AccessDeniedException.
    assert code == "ValidationException", f"expected ValidationException, got {code} message={message!r}"
    expected_message = "Invalid ARN in request: Same account ARN expected but got cross-account ARN"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control / effect-absent: the real binding still serves the same credentials
    again = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    assert again["KeyId"] == baseline["KeyId"], (
        f"expected KeyId unchanged after the rejected cross-account attempt, "
        f"baseline={baseline['KeyId']!r} again={again['KeyId']!r}"
    )
    assert again["MacKey"] == baseline["MacKey"], (
        "expected MacKey unchanged after the rejected cross-account attempt"
    )


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn) -> None:
    """Teardown that accepts only an IAM entity that is already gone (NoSuchEntity)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_active_endpoint(ctx, acm, contact: str | None = None) -> str:
    kwargs = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "sim2real-check", "Value": ctx.unique_name("acme-eab-xacct-")}],
    }
    if contact:
        kwargs["Contact"] = contact
    arn = acm.create_acme_endpoint(**kwargs)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn)))
    status = _wait_for_endpoint_status(acm, arn, {"ACTIVE", "FAILED"})
    if status != "ACTIVE":
        raise AssertionError(f"endpoint entered {status} instead of ACTIVE")
    return arn


def _wait_for_endpoint_status(
    acm, arn: str, target_statuses: set, timeout_s: float = 90.0, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last_status in target_statuses:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {arn} never reached {target_statuses}, last status={last_status}")


def _create_eab_role(ctx, iam, suffix: str) -> str:
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
    role_name = ctx.unique_name(f"sim2real-acme-eab-role-{suffix}-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


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
    deadline = time.monotonic() + min(timeout_s, ctx.time_left() or timeout_s)
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


def _swap_account(arn: str, new_account: str) -> str:
    parts = arn.split(":")
    parts[4] = new_account
    return ":".join(parts)


def _foreign_account_id(own_account: str) -> str:
    candidate = "111122223333"
    if candidate == own_account:
        candidate = "123456789013"
    return candidate


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
