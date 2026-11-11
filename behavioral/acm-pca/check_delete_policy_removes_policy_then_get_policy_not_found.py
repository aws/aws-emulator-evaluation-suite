"""delete-policy-removes-policy-then-get-policy-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-removes-policy-then-get-policy-not-found"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPolicy attaches a resource policy to an ACTIVE CA; GetPolicy reflects
    it; DeletePolicy clears it and a subsequent GetPolicy returns
    ResourceNotFoundException.
    """
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, ca_arn)
    _activate_root_ca(ctx, ca_arn)

    policy_doc = _sharing_policy_document(ca_arn, ctx.client("sts").get_caller_identity()["Account"])
    acmpca.put_policy(ResourceArn=ca_arn, Policy=json.dumps(policy_doc))

    fetched = json.loads(acmpca.get_policy(ResourceArn=ca_arn)["Policy"])
    sid = fetched["Statement"][0]["Sid"]
    assert sid == "sim2realacmpcashare", f"expected Sid 'sim2realacmpcashare' from an independent GetPolicy, got {sid!r}"
    principal = fetched["Statement"][0]["Principal"]
    assert principal == "*", f"expected Principal '*' from an independent GetPolicy, got {principal!r}"

    acmpca.delete_policy(ResourceArn=ca_arn)

    code = _error_code(lambda: acmpca.get_policy(ResourceArn=ca_arn))
    assert code == ("ResourceNotFoundException", "Could not find policy for specified resource."), (
        f"expected GetPolicy to report ResourceNotFoundException after DeletePolicy, got {code!r}"
    )


def _sharing_policy_document(ca_arn: str, own_account_id: str) -> dict:
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
                "Action": [
                    "acm-pca:DescribeCertificateAuthority",
                    "acm-pca:GetCertificate",
                    "acm-pca:GetCertificateAuthorityCertificate",
                    "acm-pca:ListPermissions",
                    "acm-pca:ListTags",
                ],
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
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
