"""import-ca-certificate-oversized-chain-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-ca-certificate-oversized-chain-rejected"
GROUP = "error-semantics"
SERVICES = ["acm-pca"]

# CertificateChain has a hard 2,097,152-byte (2 MiB) maximum in the API model.
_MAX_CHAIN_BYTES = 2 * 1024 * 1024


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportCertificateAuthorityCertificate refuses a CertificateChain over the size limit
    with ValidationException; it does not truncate the chain and activate the CA."""
    acm = ctx.client("acm-pca")
    # Bypass client-side blob-length checks so the oversized payload actually
    # reaches the service instead of being rejected locally by botocore.
    acm._client_config.parameter_validation = False

    ca_arn = _create_ca(ctx)
    cert_pem = _self_sign_root_cert(ctx, ca_arn)
    oversized_chain = b"-----BEGIN CERTIFICATE-----\n" + (b"A" * (_MAX_CHAIN_BYTES + 1024))

    def _import_with_oversized_chain():
        acm.import_certificate_authority_certificate(
            CertificateAuthorityArn=ca_arn,
            Certificate=cert_pem,
            CertificateChain=oversized_chain,
        )

    refusal = _error(_import_with_oversized_chain)
    # Empirically, real AWS rejects an oversized CertificateChain with the generic
    # ValidationException (length-constraint violation), not MalformedCertificateException
    # (which is reserved for a chain that parses within size limits but fails to decode/verify).
    assert refusal == (
        "ValidationException",
        "1 validation error detected: Value at 'certificateChain' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_MAX_CHAIN_BYTES}",
    ), refusal

    # effect absent: the CA was not activated by the rejected import
    status = acm.describe_certificate_authority(CertificateAuthorityArn=ca_arn)["CertificateAuthority"]["Status"]
    assert status == "PENDING_CERTIFICATE", f"expected CA to remain PENDING_CERTIFICATE, got {status}"

    # positive control: importing the same certificate without an oversized chain succeeds
    acm.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=cert_pem)
    _wait_for_status(ctx, ca_arn, "ACTIVE")


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if it raises. An unexpected
    SUCCESS raises here, because turning acceptance into a falsy sentinel would let an
    over-permissive target read as a mere code mismatch instead of the real defect."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects an oversized CertificateChain, but the call SUCCEEDED "
        f"and returned {result!r}"
    )


def _create_ca(ctx, key_algorithm="RSA_2048", signing_algorithm="SHA256WITHRSA", ca_type="ROOT"):
    acm = ctx.client("acm-pca")
    cn = ctx.unique_name("sim2real-pca-")
    resp = acm.create_certificate_authority(
        CertificateAuthorityConfiguration={
            "KeyAlgorithm": key_algorithm,
            "SigningAlgorithm": signing_algorithm,
            "Subject": {"CommonName": cn},
        },
        CertificateAuthorityType=ca_type,
        Tags=[{"Key": "sim2real-check", "Value": "import-ca-certificate-oversized-chain-rejected"}],
    )
    arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _delete_ca(ctx, arn))
    _wait_for_csr_ready(ctx, arn)
    return arn


def _delete_ca(ctx, arn):
    """An ACTIVE CA cannot be deleted, so disable it first (the check activates it)."""
    acm = ctx.client("acm-pca")
    try:
        status = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status == "DELETED":
        return
    if status == "ACTIVE":
        acm.update_certificate_authority(CertificateAuthorityArn=arn, Status="DISABLED")
        _wait_for_status(ctx, arn, "DISABLED")
    acm.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)


def _wait_for_csr_ready(ctx, arn, timeout_s=90.0, interval_s=2.0):
    acm = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if status in ("PENDING_CERTIFICATE", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError("CA never left CREATING state")


def _get_csr(ctx, arn, timeout_s=60.0, interval_s=2.0):
    acm = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acm.get_certificate_authority_csr(CertificateAuthorityArn=arn)["Csr"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError("CSR never became available")


def _get_certificate(ctx, ca_arn, cert_arn, timeout_s=60.0, interval_s=2.0):
    acm = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return acm.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)["Certificate"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "RequestInProgressException":
                raise
            time.sleep(interval_s)
    raise AssertionError("certificate never became available")


def _wait_for_status(ctx, arn, target, timeout_s=90.0, interval_s=2.0):
    acm = ctx.client("acm-pca")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = acm.describe_certificate_authority(CertificateAuthorityArn=arn)["CertificateAuthority"]["Status"]
        if status == target:
            return
        time.sleep(interval_s)
    raise AssertionError(f"CA never reached {target} status")


def _self_sign_root_cert(ctx, ca_arn, signing_algorithm="SHA256WITHRSA", validity_years=10):
    acm = ctx.client("acm-pca")
    csr = _get_csr(ctx, ca_arn)
    cert_arn = acm.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm=signing_algorithm,
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity={"Value": validity_years, "Type": "YEARS"},
    )["CertificateArn"]
    return _get_certificate(ctx, ca_arn, cert_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
