"""api-passthrough-applies-only-under-a-passthrough-template."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-passthrough-applies-only-under-a-passthrough-template"
GROUP = "representation"
SERVICES = ["acm-pca"]

# DeleteCertificateAuthority models PermanentDeletionTimeInDays as 7..30; 7 is the shortest
# window the service allows. A CA in DELETED status is not billed ("For all status values
# except DELETED and FAILED, you are billed for the CA" -- privateca userguide
# PcaUpdateStatus.html), so reaching DELETED is the whole cost objective of the teardown.
_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
# The twin. Identical base template, differing ONLY in whether API passthrough is permitted.
_BASE_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_PASSTHROUGH_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate_APIPassthrough/V1"
# A short-lived-mode CA is $50/CA/month rather than $400, and issues certificates of at most
# 7 days -- all this check needs (aws.amazon.com/private-ca/pricing).
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7

# Values that exist ONLY in the CSR, and values that exist ONLY in the ApiPassthrough
# argument. Keeping them disjoint is what makes "which source won" a decidable question.
_CSR_CN = "csr-subject.sim2real.invalid"
_CSR_DNS = "csr-san.sim2real.invalid"
_API_CN = "api-subject.sim2real.invalid"
_API_DNS = "api-san.sim2real.invalid"
_API_ORG = "sim2real-api-passthrough-org"

_ACTIVATE_TIMEOUT_S = 240.0
_TEARDOWN_TIMEOUT_S = 420.0


# ===== helpers (self-contained) =====
# CA lifecycle helpers: a check travels as one self-contained file, so they live here.


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _require_local_crypto() -> None:
    """Decided BEFORE any create: an absent parser cannot be discovered after billing starts."""
    from cryptography import x509  # noqa: F401


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED".

    DeleteCertificateAuthority accepts only CREATING, PENDING_CERTIFICATE, DISABLED or
    FAILED, so an ACTIVE CA must be DISABLED first. Issuing the delete is not enough on its
    own: the meter stops on the DELETED status, not on the API call, so this polls for that
    status and RAISES if it never arrives rather than swallowing the error.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
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
                pass  # teardown-only: re-read the status and retry on the next pass
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn,
                PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: certificate authority {ca_arn} never reached "
        f"Status=DELETED within {_TEARDOWN_TIMEOUT_S}s (last observed {last_status!r}). It is "
        f"STILL BILLING. Delete it manually: UpdateCertificateAuthority(Status='DISABLED') "
        f"then DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, scenario):
    """Create a ROOT CA and register its teardown AT CREATION TIME, before anything asserts.

    Tagged because a CA's only handle is a server-minted UUID and it carries no name, so the
    tag is what makes a stranded CA discoverable after the run.
    """
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")[:64]},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": _USAGE_MODE,
        "Tags": [{"Key": "sim2real", "Value": scenario}],
    }
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            throttles = ("ThrottlingException", "Throttling", "RequestLimitExceeded")
            if code in throttles and attempt < 5:
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


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate, polling through RequestInProgressException until signing completes.

    RequestInProgressException is the observable condition that signing is asynchronous --
    there is no sleep standing in for it. Returns (certificate_pem, chain_pem_or_None).
    """
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RequestInProgressException":
                return None
            raise

    got = _poll_until(
        _probe, lambda v: bool(v and v.get("Certificate")),
        timeout_s=timeout_s, interval_s=2.0,
        description=f"GetCertificate returning a signed certificate for {cert_arn}",
    )
    return got["Certificate"], got.get("CertificateChain")


def _activate_root_ca(ctx, ca_arn, *, timeout_s):
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE by having ACM-PCA sign its own CSR.

    The documented root-CA installation sequence (privateca userguide, "Install a root CA
    certificate"). Returns the CA certificate PEM.
    """
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0, description="CA reaching PENDING_CERTIFICATE",
    )
    csr_pem = _fetch_csr(ctx, ca_arn, timeout_s=timeout_s)
    root_cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_ROOT_TEMPLATE,
        Validity={"Value": 3, "Type": "YEARS"},
    )["CertificateArn"]
    ca_cert_pem, _ = _await_certificate(ctx, ca_arn, root_cert_arn, timeout_s=timeout_s)
    pca.import_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn, Certificate=ca_cert_pem.encode("ascii")
    )
    _poll_until(
        lambda: _describe(ctx, ca_arn), lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


def _new_csr(common_name, dns_name):
    """A locally generated RSA-2048 key and a PKCS#10 request carrying CN + a DNS SAN.

    The key never leaves this process, so the CSR's contribution to the issued certificate is
    a falsifiable claim rather than something the service could have invented.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _dns_sans(cert):
    """The DNSName entries of the certificate's subjectAltName, or [] if the extension is
    absent. The empty default is correct here: it feeds equality-to-an-exact-set assertions
    and a `not in` assertion, so an absent extension FAILS them rather than satisfying them.
    """
    from cryptography import x509

    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return ext.value.get_values_for_type(x509.DNSName)


def _common_names(cert):
    from cryptography.x509.oid import NameOID

    return [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]


def _organizations(cert):
    from cryptography.x509.oid import NameOID

    return [a.value for a in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An `ApiPassthrough` argument changes the issued certificate ONLY when the TemplateArn is an
    APIPassthrough variant; under the base template the same argument is ignored and the CSR's own
    subject and SAN are signed (one CA, one CSR, two issues differing only in template)."""
    _require_local_crypto()

    from cryptography import x509

    pca = ctx.client("acm-pca")
    scenario = "acm-pca-api-passthrough-template-gated"

    ca_arn = _create_ca(ctx, scenario)
    _activate_root_ca(ctx, ca_arn, timeout_s=_ACTIVATE_TIMEOUT_S)

    ca_status = _describe(ctx, ca_arn)["Status"]
    assert ca_status == "ACTIVE", (
        f"the CA must be ACTIVE before either leg is issued, so that a refusal cannot be "
        f"blamed on CA state; DescribeCertificateAuthority reports {ca_status!r}"
    )

    # ONE CSR, used by BOTH legs. Anything that differs between the two issued certificates
    # is therefore attributable to the TemplateArn and nothing else.
    csr_pem = _new_csr(_CSR_CN, _CSR_DNS)

    api_passthrough = {
        "Subject": {"CommonName": _API_CN, "Organization": _API_ORG},
        "Extensions": {"SubjectAlternativeNames": [{"DnsName": _API_DNS}]},
    }

    issued = {}
    for label, template in (("ignored", _BASE_TEMPLATE), ("applied", _PASSTHROUGH_TEMPLATE)):
        cert_arn = pca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr_pem.encode("ascii"),
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn=template,
            ApiPassthrough=api_passthrough,
            Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
        )["CertificateArn"]
        pem, _ = _await_certificate(ctx, ca_arn, cert_arn, timeout_s=_ACTIVATE_TIMEOUT_S)
        issued[label] = x509.load_pem_x509_certificate(pem.encode("ascii"))

    base_cert = issued["ignored"]
    pass_cert = issued["applied"]

    # ---- Leg A: the base template must have IGNORED the ApiPassthrough argument ----
    base_cns = _common_names(base_cert)
    assert base_cns == [_CSR_CN], (
        f"under the BASE template {_BASE_TEMPLATE} the ApiPassthrough Subject must be "
        f"ignored and the CSR subject signed instead: expected CN exactly [{_CSR_CN!r}], "
        f"the issued certificate carries {base_cns!r}"
    )
    base_orgs = _organizations(base_cert)
    assert base_orgs == [], (
        f"the base template must not copy the ApiPassthrough Organization into the subject: "
        f"expected no O= RDN, the issued certificate carries {base_orgs!r}"
    )
    base_sans = _dns_sans(base_cert)
    assert base_sans == [_CSR_DNS], (
        f"under the base template the subjectAltName must come from the CSR alone: expected "
        f"exactly [{_CSR_DNS!r}], the issued certificate carries {base_sans!r}"
    )
    assert _API_DNS not in base_sans, (
        f"the API-supplied DNS name {_API_DNS!r} leaked into a certificate issued under the "
        f"base template, which does not permit API passthrough; SANs were {base_sans!r}"
    )

    # ---- Leg B: the _APIPassthrough variant must have APPLIED it ----
    pass_cns = _common_names(pass_cert)
    assert pass_cns == [_API_CN], (
        f"under {_PASSTHROUGH_TEMPLATE} the API-supplied Subject takes priority over the "
        f"CSR's: expected CN exactly [{_API_CN!r}], the issued certificate carries "
        f"{pass_cns!r} (the CSR asked for {_CSR_CN!r})"
    )
    pass_orgs = _organizations(pass_cert)
    assert pass_orgs == [_API_ORG], (
        f"the API-supplied Organization must land as an O= RDN under the passthrough "
        f"template: expected exactly [{_API_ORG!r}], got {pass_orgs!r}"
    )
    pass_sans = _dns_sans(pass_cert)
    assert _API_DNS in pass_sans, (
        f"the API-supplied subjectAltName {_API_DNS!r} must appear in a certificate issued "
        f"under {_PASSTHROUGH_TEMPLATE}; the issued certificate carries {pass_sans!r}"
    )

    # ---- The twin closes: the SAME ApiPassthrough produced DIFFERENT bytes ----
    # A target that treats the two template ARNs as interchangeable cannot satisfy this, and
    # neither can one that ignores ApiPassthrough on both legs.
    assert set(pass_sans) != set(base_sans), (
        f"both legs submitted a byte-identical ApiPassthrough and the same CSR, so the two "
        f"issued certificates must differ in subjectAltName: base template produced "
        f"{base_sans!r} and the passthrough template produced {pass_sans!r}"
    )
    assert pass_cns != base_cns, (
        f"both legs submitted a byte-identical ApiPassthrough and the same CSR, so the two "
        f"issued subjects must differ: base template produced CN {base_cns!r}, passthrough "
        f"template produced CN {pass_cns!r}"
    )
    # Both certificates came from the SAME CA in the SAME instant, so a divergence in issuer
    # would mean the two legs were not actually comparable.
    assert pass_cert.issuer == base_cert.issuer, (
        f"the two legs must be signed by the same CA identity for the comparison above to "
        f"mean anything: {pass_cert.issuer.rfc4514_string()!r} vs "
        f"{base_cert.issuer.rfc4514_string()!r}"
    )
    assert pass_cert.serial_number != base_cert.serial_number, (
        f"the two legs must be two distinct certificates, but both report serial "
        f"{base_cert.serial_number:x} -- GetCertificate returned the same object twice"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
