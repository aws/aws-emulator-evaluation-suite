"""describe-nonexistent-acme-external-account-binding-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-acme-external-account-binding-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAcmeExternalAccountBinding on a well-formed but unknown ARN raises
    ResourceNotFoundException; the identical call against a real binding (the positive control)
    succeeds."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    role_arn = _create_eab_role(ctx)
    binding_arn = _create_binding_with_retry(ctx, endpoint_arn, role_arn)[
        "ExternalAccountBinding"
    ]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: _delete_binding_ignore_errors(ctx, binding_arn))

    positive = acm.describe_acme_external_account_binding(
        AcmeExternalAccountBindingArn=binding_arn
    )["ExternalAccountBinding"]
    assert positive["AcmeExternalAccountBindingArn"] == binding_arn, (
        f"positive control failed: expected to describe real binding {binding_arn!r}, got {positive!r}"
    )

    account = _account_id(ctx)
    # Matches arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:acme-endpoint/[a-zA-Z0-9-]+/acme-external-account-binding/[a-zA-Z0-9-]+
    fake_arn = (
        f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4()}"
        f"/acme-external-account-binding/{uuid.uuid4()}"
    )

    code, message = _error(
        lambda: acm.describe_acme_external_account_binding(
            AcmeExternalAccountBindingArn=fake_arn
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for unknown external account binding, got {code!r}"
    )
    expected_message = f"Could not find ACME external account binding {fake_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_acme_endpoint(ctx, contact: str = "NOT_REQUIRED") -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact=contact,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_endpoint_ignore_errors(ctx, arn))
    status = _wait_for_endpoint_terminal(ctx, arn)
    if status != "ACTIVE":
        raise AssertionError(f"AcmeEndpoint {arn} settled in status {status}, expected ACTIVE")
    return arn


def _wait_for_endpoint_terminal(ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if last in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} never left a non-terminal status; last={last}")


def _delete_endpoint_ignore_errors(ctx, arn: str) -> None:
    acm = ctx.client("acm")
    acm.delete_acme_endpoint(AcmeEndpointArn=arn)


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-eab-role-")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role_ignore_errors(ctx, role_name))
    return resp["Role"]["Arn"]


def _delete_role_ignore_errors(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_binding_with_retry(ctx, endpoint_arn: str, role_arn: str, timeout_s: float = 60.0):
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                # IAM role trust-policy propagation lag.
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")


def _delete_binding_ignore_errors(ctx, binding_arn: str) -> None:
    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
