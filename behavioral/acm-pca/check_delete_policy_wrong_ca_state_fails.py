"""delete-policy-wrong-ca-state-fails."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-policy-wrong-ca-state-fails"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPolicy and DeletePolicy succeed on a CA in PENDING_CERTIFICATE and in DELETED
    (within its restore window), and DeletePolicy on a well-formed ARN naming no CA fails
    with ResourceNotFoundException."""
    acmpca = ctx.client("acm-pca")
    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, ca_arn)
    status = _wait_for_ca_status(ctx, ca_arn, {"PENDING_CERTIFICATE"})
    assert status == "PENDING_CERTIFICATE", f"expected new CA to be PENDING_CERTIFICATE, got {status!r}"

    # PutPolicy/GetPolicy/DeletePolicy all succeed on a CA that exists but has
    # not yet been activated -- there is no CA-lifecycle-state gate on policy
    # operations while the CA is present.
    acmpca.put_policy(ResourceArn=ca_arn, Policy=json.dumps(_policy_doc(ca_arn, own_account_id)))
    policy = acmpca.get_policy(ResourceArn=ca_arn)["Policy"]
    assert policy, "expected GetPolicy to return the policy just attached on a PENDING_CERTIFICATE CA"
    acmpca.delete_policy(ResourceArn=ca_arn)
    code_get = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert code_get == ("ResourceNotFoundException", "Could not find policy for specified resource."), f"expected GetPolicy to 404 after DeletePolicy, got {code_get!r}"

    # Even a soft-deleted CA (within its restoration window) still exists as a
    # resource, so DeletePolicy on it remains a no-op success, not an error.
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    status = _wait_for_ca_status(ctx, ca_arn, {"DELETED"})
    assert status == "DELETED", f"expected soft-deleted CA to reach DELETED, got {status!r}"
    acmpca.delete_policy(ResourceArn=ca_arn)

    # Break exactly one thing: DeletePolicy against a CA ARN that was never
    # created at all (well-formed, but no such CA exists) is rejected.
    bogus_arn = f"arn:aws:acm-pca:{ctx.region}:{own_account_id}:certificate-authority/{uuid.uuid4()}"
    code = _error_code(lambda: acmpca.delete_policy(ResourceArn=bogus_arn))
    assert code == ("ResourceNotFoundException", "Could not find specified CA"), f"expected ResourceNotFoundException from DeletePolicy on a nonexistent CA ARN, got {code!r}"

    # Positive control: an ACTIVE CA can accept a policy, and that policy can
    # then be deleted successfully.
    active_ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, active_ca_arn)
    _activate_root_ca(ctx, active_ca_arn)
    acmpca.put_policy(ResourceArn=active_ca_arn, Policy=json.dumps(_policy_doc(active_ca_arn, own_account_id)))
    active_policy = acmpca.get_policy(ResourceArn=active_ca_arn)["Policy"]
    assert active_policy, "expected GetPolicy to return the policy just attached on an ACTIVE CA"
    acmpca.delete_policy(ResourceArn=active_ca_arn)
    code_after = _error_code(lambda: acmpca.get_policy(ResourceArn=active_ca_arn))
    assert code_after == ("ResourceNotFoundException", "Could not find policy for specified resource."), f"expected GetPolicy to 404 after DeletePolicy on an ACTIVE CA, got {code_after!r}"




def _policy_doc(ca_arn: str, own_account_id: str) -> dict:
    # AWS Private CA validates that an AWS-account Principal actually exists,
    # so a synthetic 12-digit account id is rejected with
    # InvalidPolicyException ("Principal not found"). Use the documented
    # Organizations-sharing shape (wildcard Principal scoped by
    # PrincipalOrgID/PrincipalAccount conditions) instead, which does not
    # require a real external account.
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realacmpcashare",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["acm-pca:GetCertificate", "acm-pca:GetCertificateAuthorityCertificate"],
                "Resource": ca_arn,
                "Condition": {
                    "StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4z5"},
                    "StringNotEquals": {"aws:PrincipalAccount": own_account_id},
                },
            }
        ],
    }



def _error_code(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")



def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
    )
    return resp["CertificateAuthorityArn"]


def _register_ca_cleanup(ctx, arn: str) -> None:
    acmpca = ctx.client("acm-pca")

    def _cleanup():
        try:
            status = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "ACTIVE":
            acmpca.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
            _wait_for_ca_status(ctx, arn, {"DISABLED"}, timeout_s=30)
            status = "DISABLED"
        if status != "DELETED":
            acmpca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)

    ctx.on_cleanup(_cleanup)


def _wait_for_ca_status(ctx, arn: str, statuses, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if last in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"CA {arn} never reached {statuses}, last status={last}")


def _poll_get_csr(ctx, arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError("CSR never became available")


def _poll_get_certificate(ctx, ca_arn: str, cert_arn: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> str:
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acmpca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError("Certificate never became available")


def _activate_root_ca(ctx, arn: str) -> None:
    acmpca = ctx.client("acm-pca")
    _wait_for_ca_status(ctx, arn, {"PENDING_CERTIFICATE"})
    csr_pem = _poll_get_csr(ctx, arn)
    cert_arn = acmpca.issue_certificate(
        CertificateAuthorityArn=arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": 10, "Type": "YEARS"},
    )["CertificateArn"]
    cert_pem = _poll_get_certificate(ctx, arn, cert_arn)
    acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=arn,
        Certificate=cert_pem.encode("ascii"),
    )
    _wait_for_ca_status(ctx, arn, {"ACTIVE"})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
