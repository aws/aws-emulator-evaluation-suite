"""e2e-external-account-binding-issuance-flow."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-external-account-binding-issuance-flow"
GROUP = "e2e"
SERVICES = ["acm"]

# AcmeDomainValidationStatus values a live (not deleted) record can show: ACM verifies the
# CNAME for up to 72 hours but may settle it within seconds, so any of them can be first.
# https://docs.aws.amazon.com/acm/latest/userguide/acm-acme-domain-validation.html
_LIVE_STATUSES = ("VALIDATING", "VALID", "INVALID")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After EAB issuance, credential retrieval and a domain validation, revoking the EAB persists
    RevokedAt: a second revoke succeeds idempotently (no ConflictException) and leaves it unchanged."""
    acm = ctx.client("acm")
    _require_acme_api(acm)
    iam = ctx.client("iam")

    endpoint_arn = _create_active_acme_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx, iam)

    eab = _create_eab_with_retry(acm, endpoint_arn, role_arn)["ExternalAccountBinding"]
    eab_arn = eab["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn))

    creds = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=eab_arn)
    assert creds["KeyId"], "KeyId must be non-empty"
    assert creds["MacKey"], "MacKey must be non-empty"

    domain_name = f"{uuid.uuid4().hex[:10]}.sim2real.example"
    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={"DnsPrevalidation": {"DomainScope": {"ExactDomain": "ENABLED"}}},
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))

    dv = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)["AcmeDomainValidation"]
    assert dv["DomainName"] == domain_name
    assert dv["Status"] in _LIVE_STATUSES, dv["Status"]

    # Revoke: the real, persisted consequence.
    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    revoked = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    revoked_at_1 = revoked.get("RevokedAt")
    assert revoked_at_1 is not None

    # Revoking again is idempotent: it succeeds again (200, no ConflictException) rather
    # than being rejected outright. What must NOT happen is the persisted RevokedAt moving
    # or disappearing: that would mean revocation is a per-call status flip rather than a
    # durably persisted state transition.
    second_response = acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    assert second_response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the redundant revoke to succeed idempotently, got "
        f"{second_response['ResponseMetadata']['HTTPStatusCode']}"
    )

    revoked_again = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert revoked_again.get("RevokedAt") == revoked_at_1, "RevokedAt must stay stable across a second revoke"


def _require_acme_api(client) -> None:
    if "CreateAcmeEndpoint" not in client.meta.service_model.operation_names:
        raise AssertionError(
            "installed botocore lacks the ACM ACME endpoint operations "
            "(CreateAcmeEndpoint/CreateAcmeExternalAccountBinding/...) -- upgrade botocore/boto3 "
            "to a version that models the ACM ACME endpoint API surface"
        )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _create_active_acme_endpoint(ctx, acm) -> str:
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"ACME endpoint entered {status}, expected ACTIVE")
    return arn


def _create_eab_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-acm-eab-role-")
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
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                "Resource": "*",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="acme-eab-permissions", PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="acme-eab-permissions"))
    return role_arn


def _create_eab_with_retry(acm, endpoint_arn, role_arn, timeout_s: float = 45.0):
    # ACM assumes the role synchronously (session "acme-verification") when creating the EAB,
    # so it can briefly fail with AccessDeniedException while the new role's trust policy
    # propagates through IAM. Retry only that specific, transient code.
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Expiration={"Value": 7, "Type": "DAYS"},
                Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "AccessDeniedException":
                raise
            time.sleep(3)
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded, last error={last_code}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
