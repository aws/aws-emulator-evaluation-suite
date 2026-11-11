"""ca-csr-pem-structure-matches-requested-configuration."""
from __future__ import annotations

import base64
import re
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "ca-csr-pem-structure-matches-requested-configuration"
GROUP = 'lifecycle'
SERVICES = ['acm-pca']

# A private CA bills hourly from creation, even while PENDING_CERTIFICATE, so exactly one
# never-activated CA is created. 7 is the shortest PermanentDeletionTimeInDays allowed (7..30).
_MIN_DELETION_DAYS = 7

_PEM_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----"
_PEM_END = "-----END CERTIFICATE REQUEST-----"
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE REQUEST-----\r?\n(.*?)\r?\n-----END CERTIFICATE REQUEST-----",
    re.S,
)

# X.500 attribute OIDs, so the subject comparison does not depend on any library's
# short-name table.
_OID_CN = "2.5.4.3"
_OID_C = "2.5.4.6"
_OID_L = "2.5.4.7"
_OID_ST = "2.5.4.8"
_OID_O = "2.5.4.10"
_OID_OU = "2.5.4.11"
# sha256WithRSAEncryption (PKCS#1).
_OID_SHA256_RSA = "1.2.840.113549.1.1.11"

# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Poll out of CREATING, disable if ACTIVE, then delete with the minimum 7-day window.

    DeleteCertificateAuthority refuses an ACTIVE or still-settling CA; raise rather than leak.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 300
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError:
            return  # not addressable any more; nothing left to bill
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError:
                pass
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn,
                PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: could not delete certificate authority {ca_arn} within "
        f"300s (last observed Status={last_status!r}). It is STILL BILLING. Delete it "
        f"manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, **overrides):
    """Create a never-activated SHORT_LIVED ROOT CA and register its teardown at creation.

    Retries on throttling, since CreateCertificateAuthority has a low request-rate limit.
    """
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    body.update(overrides)
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _fetch_csr(ctx, ca_arn, *, timeout_s):
    """GetCertificateAuthorityCsr, polling through the creation-in-progress guard."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    return _poll_until(
        _probe, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCertificateAuthorityCsr returns one PKCS#10 PEM matching the CA's configuration:
    exact subject attributes, RSA-2048, sha256WithRSA, a valid self-signature and exact KeyUsage.

    Reference: https://docs.aws.amazon.com/privateca/latest/APIReference/API_GetCertificateAuthorityCsr.html
    """
    pca = ctx.client("acm-pca")
    timeout_s = 180

    common_name = ctx.unique_name("sim2real-behav-pca-csr-").rstrip("-")
    subject = {
        "CommonName": common_name,
        "Country": "US",
        "State": "Washington",
        "Locality": "Seattle",
        "Organization": "sim2real",
        "OrganizationalUnit": "test",
    }
    requested_key_usage = {"DigitalSignature": True, "KeyCertSign": True, "CRLSign": True}

    ca_arn = _create_ca(ctx, **{
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": subject,
            "CsrExtensions": {"KeyUsage": dict(requested_key_usage)},
        },
    })

    # Assert the exact terminal pre-activation status, not a tolerant status tuple.
    ca = _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )
    assert ca["Status"] == "PENDING_CERTIFICATE", ca["Status"]

    csr_pem = _fetch_csr(ctx, ca_arn, timeout_s=timeout_s)

    # ---- PEM envelope, stdlib only ----
    assert isinstance(csr_pem, str), f"Csr must be a PEM string, got {type(csr_pem).__name__}"
    blocks = _PEM_BLOCK_RE.findall(csr_pem)
    assert len(blocks) == 1, (
        f"GetCertificateAuthorityCsr must return exactly one PEM block, found "
        f"{len(blocks)} in {csr_pem[:120]!r}"
    )
    assert csr_pem.strip().startswith(_PEM_BEGIN), (
        f"CSR PEM armor must start with {_PEM_BEGIN!r}, got {csr_pem[:64]!r}"
    )
    assert csr_pem.strip().endswith(_PEM_END), (
        f"CSR PEM armor must end with {_PEM_END!r}, got {csr_pem[-64:]!r}"
    )
    der = base64.b64decode("".join(blocks[0].split()), validate=True)
    assert der[:1] == b"\x30", (
        f"the decoded CSR must be a DER SEQUENCE (leading tag 0x30), got "
        f"0x{der[:1].hex()}; the body is not a PKCS#10 structure"
    )
    assert len(der) > 300, (
        f"the decoded CSR is {len(der)} bytes; an RSA-2048 PKCS#10 request with a "
        f"six-attribute subject cannot be that small"
    )

    # ---- Parsed structure ----
    # cryptography is a declared dependency of the suite (pyproject.toml); a missing
    # module is the runner's problem, not a target failure, so let ImportError propagate.
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa

    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))

    # Exactly the six requested attributes; RDN order is not documented, so it is not asserted.
    got = {(a.oid.dotted_string, a.value) for a in csr.subject}
    want = {
        (_OID_CN, common_name),
        (_OID_C, "US"),
        (_OID_ST, "Washington"),
        (_OID_L, "Seattle"),
        (_OID_O, "sim2real"),
        (_OID_OU, "test"),
    }
    assert got == want, (
        f"CSR subject attributes do not match the requested Subject.\n"
        f"missing: {sorted(want - got)}\nunexpected: {sorted(got - want)}"
    )
    assert len(list(csr.subject)) == len(want), (
        f"CSR subject has {len(list(csr.subject))} attributes, expected {len(want)} "
        f"(duplicate RDNs)"
    )

    pub = csr.public_key()
    assert isinstance(pub, rsa.RSAPublicKey), (
        f"CA was created with KeyAlgorithm=RSA_2048 but the CSR public key is "
        f"{type(pub).__name__}"
    )
    assert pub.key_size == 2048, (
        f"CA was created with KeyAlgorithm=RSA_2048 but the CSR public key is "
        f"{pub.key_size} bits"
    )
    assert csr.signature_algorithm_oid.dotted_string == _OID_SHA256_RSA, (
        f"CA was created with SigningAlgorithm=SHA256WITHRSA so the CSR must be signed "
        f"with sha256WithRSAEncryption ({_OID_SHA256_RSA}), got "
        f"{csr.signature_algorithm_oid.dotted_string}"
    )
    # Functional round-trip: the signature must verify against the CSR's own public key.
    assert csr.is_signature_valid, (
        "the CSR's self-signature does not verify against its own embedded public key; "
        "the PEM is structurally shaped but cryptographically inconsistent"
    )

    ku = csr.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True, "CsrExtensions requested DigitalSignature=True"
    assert ku.key_cert_sign is True, "CsrExtensions requested KeyCertSign=True"
    assert ku.crl_sign is True, "CsrExtensions requested CRLSign=True"
    # Bits NOT requested must be off; setting every bit is over-permissive for a CA.
    assert ku.content_commitment is False, "NonRepudiation was not requested but is set"
    assert ku.key_encipherment is False, "KeyEncipherment was not requested but is set"
    assert ku.data_encipherment is False, "DataEncipherment was not requested but is set"
    assert ku.key_agreement is False, "KeyAgreement was not requested but is set"

    # And the CA's own configuration must echo what we asked for, so the CSR and the
    # control-plane view agree.
    cfg = _describe(ctx, ca_arn)["CertificateAuthorityConfiguration"]
    assert cfg["Subject"]["CommonName"] == common_name, cfg["Subject"]
    assert cfg["KeyAlgorithm"] == "RSA_2048", cfg["KeyAlgorithm"]
    assert cfg["SigningAlgorithm"] == "SHA256WITHRSA", cfg["SigningAlgorithm"]
    # Guard against a stray unused-import lint on `pca`.
    assert pca is not None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
