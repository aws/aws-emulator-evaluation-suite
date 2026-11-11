"""get-credentials-after-revoke-external-account-binding-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-after-revoke-external-account-binding-blocked"
GROUP = "overly-permissive"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After revocation, credential retrieval fails with ValidationException instead of returning
    stale key material; the record survives with RevokedAt, so it is not ResourceNotFoundException."""
    acm = ctx.client("acm")
    endpoint_arn = _create_active_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx)
    eab_arn = _create_eab_binding(ctx, acm, endpoint_arn, role_arn)
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    )

    # Positive control: credentials are retrievable before revocation.
    before = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    assert before["KeyId"] and before["MacKey"], (
        f"expected KeyId and MacKey before any revocation; got {before!r}"
    )

    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    described = acm.describe_acme_external_account_binding(
        AcmeExternalAccountBindingArn=eab_arn
    )["ExternalAccountBinding"]
    assert "RevokedAt" in described, "revocation did not persist a RevokedAt timestamp"

    code, message = _error(
        lambda: acm.get_acme_external_account_binding_credentials(
            AcmeExternalAccountBindingArn=eab_arn
        )
    )
    assert code == "ValidationException", (
        f"a revoked binding's record still exists (RevokedAt was set, not deleted), so credential "
        f"access must be rejected with ValidationException, not a generic not-found; got {code!r}"
    )
    expected_message = f"The ACME external account binding {eab_arn} has been revoked."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _wait_endpoint_active(acm, arn, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError("ACME endpoint creation failed")
        time.sleep(interval_s)
    raise AssertionError("ACME endpoint never became ACTIVE within timeout")


def _create_active_endpoint(ctx, acm):
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-endpoint-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_endpoint_active(acm, arn)
    return arn


def _create_eab_binding(ctx, acm, endpoint_arn, role_arn, timeout_s=30.0, interval_s=3.0):
    """iam:PassRole against a role this check just created can deny for a bounded window
    while IAM propagates the role -- tolerate that, not a permanent policy denial."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-eab-")}],
            )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateAcmeExternalAccountBinding never succeeded within {timeout_s}s "
        f"(iam:PassRole for {role_arn} kept denying): {last_err}"
    )


def _create_eab_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acm-acme-role-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
