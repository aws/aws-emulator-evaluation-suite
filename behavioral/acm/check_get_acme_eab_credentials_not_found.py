"""get-acme-eab-credentials-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-acme-eab-credentials-not-found"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAcmeExternalAccountBindingCredentials for a binding id that was never
    created returns ResourceNotFoundException; the same call against a real,
    existing binding returns usable KeyId/MacKey credentials (positive control)."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    endpoint_id = endpoint_arn.rsplit("/", 1)[-1]

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    missing_binding_arn = (
        f"arn:aws:acm:{ctx.region}:{account_id}:acme-endpoint/{endpoint_id}"
        "/acme-external-account-binding/00000000-0000-0000-0000-000000000000"
    )
    code, message = _error(
        lambda: acm.get_acme_external_account_binding_credentials(
            AcmeExternalAccountBindingArn=missing_binding_arn
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created binding, got {code!r}"
    )
    expected_message = f"Could not find ACME external account binding {missing_binding_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    role_arn = _create_eab_role(ctx)
    create_resp = _create_binding_with_retry(ctx, endpoint_arn, role_arn)
    binding_arn = create_resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: _delete_binding_ignore_errors(ctx, binding_arn))

    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=binding_arn
    )
    assert creds.get("KeyId"), f"positive control: expected a KeyId, got {creds!r}"
    assert creds.get("MacKey"), f"positive control: expected a MacKey, got {creds!r}"


def _error(fn):
    """Run fn, which must be refused; return the (code, message) of the refusal."""
    from botocore.exceptions import ClientError

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
    from botocore.exceptions import ClientError

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
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_binding_with_retry(ctx, endpoint_arn: str, role_arn: str, timeout_s: float = 60.0):
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")


def _delete_binding_ignore_errors(ctx, binding_arn: str) -> None:
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
