"""restore-certificate-authority-from-deleted-window."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "restore-certificate-authority-from-deleted-window"
GROUP = "state-machine"
SERVICES = ["acm-pca"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CA deleted within its restorable window restores to its pre-deletion status
    (DISABLED, not ACTIVE), and once re-enabled issues a certificate again."""
    acmpca = ctx.client("acm-pca")
    ca_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, ca_arn)
    _activate_root_ca(ctx, ca_arn)
    active_status = _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"})
    assert active_status == "ACTIVE", f"expected activation to reach ACTIVE, got {active_status}"

    # Disable (required before delete) then delete with a real restoration window.
    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="DISABLED")
    _wait_for_ca_status(ctx, ca_arn, {"DISABLED"})
    acmpca.delete_certificate_authority(CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=7)
    desc = _wait_for_ca_status(ctx, ca_arn, {"DELETED"}, return_full=True)
    assert desc["Status"] == "DELETED", f"expected DELETED after delete, got {desc['Status']}"
    assert "RestorableUntil" in desc, f"a DELETED CA must report RestorableUntil; keys={sorted(desc)}"

    # Restore within the window: status goes back to its pre-deletion value.
    acmpca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    restored_status = _wait_for_ca_status(ctx, ca_arn, {"DISABLED", "ACTIVE"})
    assert restored_status == "DISABLED", f"expected restore to pre-deletion DISABLED, got {restored_status}"

    # Now prove the CA is genuinely usable again: re-enable and issue a certificate.
    acmpca.update_certificate_authority(CertificateAuthorityArn=ca_arn, Status="ACTIVE")
    reenabled_status = _wait_for_ca_status(ctx, ca_arn, {"ACTIVE"})
    assert reenabled_status == "ACTIVE", f"expected re-enable to reach ACTIVE, got {reenabled_status}"

    csr_pem = _throwaway_csr(ctx)
    issued = acmpca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        Validity={"Value": 30, "Type": "DAYS"},
    )
    assert issued["CertificateArn"].startswith(ca_arn + "/certificate/"), (
        f"expected certificate arn under {ca_arn}/certificate/, got {issued['CertificateArn']}"
    )
    cert_pem = _poll_get_certificate(ctx, ca_arn, issued["CertificateArn"])
    assert "BEGIN CERTIFICATE" in cert_pem, f"GetCertificate did not return a PEM certificate: {cert_pem!r}"



def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _create_root_ca(ctx) -> str:
    acmpca = ctx.client("acm-pca")
    resp = acmpca.create_certificate_authority(
        CertificateAuthorityType="ROOT",
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-acmpca-")[:64]},
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _wait_for_ca_status(ctx, arn: str, statuses, timeout_s: float = 90.0, interval_s: float = 2.0, return_full: bool = False):
    acmpca = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]
        last = desc["Status"]
        if last in statuses:
            return desc if return_full else last
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
    """Follows the documented AWS CLI process for installing a root CA
    certificate: fetch the CA's own CSR, self-issue a root certificate using the
    RootCACertificate template, then import it back in. Uses only ACM PCA API
    calls (no external crypto needed).
    """
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


def _throwaway_csr(ctx) -> str:
    """Obtains a syntactically valid PKCS#10 CSR PEM without any external crypto
    dependency, by creating a second, disposable ROOT CA purely to harvest its
    self-generated CSR. The CSR does not need any relationship to the CA it will
    later be presented to -- IssueCertificate only requires a structurally valid,
    self-consistent CSR.
    """
    throwaway_arn = _create_root_ca(ctx)
    _register_ca_cleanup(ctx, throwaway_arn)
    csr_pem = _poll_get_csr(ctx, throwaway_arn)
    return csr_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
