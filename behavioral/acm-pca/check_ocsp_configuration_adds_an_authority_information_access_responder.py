"""ocsp-configuration-adds-an-authority-information-access-responder."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ocsp-configuration-adds-an-authority-information-access-responder"
GROUP = "server-side"
SERVICES = ["acm-pca"]

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7

_ACTIVATE_TIMEOUT_S = 180.0
_LEAF_TIMEOUT_S = 90.0
_TEARDOWN_TIMEOUT_S = 420.0


# ===== CA lifecycle helpers (self-contained) =====
# A check travels as one self-contained file, so they live here.


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


def _create_ca(ctx, scenario, **overrides):
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
    body.update(overrides)
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


def _new_csr(common_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it.

    The key never leaves this process, so the issued certificate's public key is a falsifiable
    claim rather than something the service could have invented.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _ocsp_uris(cert):
    """URIs of the certificate's AIA accessDescriptions whose method is id-ad-ocsp, or [].

    The empty default is the correct polarity: it feeds an `== []` assertion on the
    OCSP-disabled leg and a non-empty assertion on the enabled leg, so an absent extension
    FAILS the enabled leg rather than satisfying it.
    """
    from cryptography import x509
    from cryptography.x509.oid import AuthorityInformationAccessOID

    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return []
    uris = []
    for desc in ext.value:
        if desc.access_method != AuthorityInformationAccessOID.OCSP:
            continue
        if isinstance(desc.access_location, x509.UniformResourceIdentifier):
            uris.append(desc.access_location.value)
    return uris


def _issue_leaf(ctx, ca_arn, csr_pem):
    from cryptography import x509

    cert_arn = ctx.client("acm-pca").issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
    )["CertificateArn"]
    pem, _ = _await_certificate(ctx, ca_arn, cert_arn, timeout_s=_LEAF_TIMEOUT_S)
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def _set_ocsp(ctx, ca_arn, enabled, **extra):
    """Set the CA's OcspConfiguration and wait until Describe reports it in effect."""
    cfg = {"Enabled": enabled}
    cfg.update(extra)
    ctx.client("acm-pca").update_certificate_authority(
        CertificateAuthorityArn=ca_arn, RevocationConfiguration={"OcspConfiguration": cfg}
    )
    return _poll_until(
        lambda: _describe(ctx, ca_arn).get("RevocationConfiguration", {}).get(
            "OcspConfiguration", {}
        ),
        lambda c: c.get("Enabled") is enabled,
        timeout_s=_ACTIVATE_TIMEOUT_S, interval_s=3.0,
        description=(
            f"DescribeCertificateAuthority reporting OcspConfiguration.Enabled={enabled} "
            f"for {ca_arn}"
        ),
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """`OcspConfiguration.Enabled` changes every certificate the CA then issues: an AIA OCSP
    accessDescription is present when on and absent when off, and `OcspCustomCname` decides the
    host of that URI (two CAs, one CSR, parsed from the GetCertificate DER)."""
    _require_local_crypto()

    scenario = "acm-pca-ocsp-aia-responder"

    # Both CAs first, so both teardowns are registered before anything can assert.
    off_ca = _create_ca(ctx, scenario)
    on_ca = _create_ca(ctx, scenario)
    for arn in (off_ca, on_ca):
        _activate_root_ca(ctx, arn, timeout_s=_ACTIVATE_TIMEOUT_S)

    # A CNAME this run invented: no recording can carry it, and a target echoing a canned
    # responder URL cannot contain it.
    custom_cname = ctx.unique_name("ocsp-").lower().rstrip("-") + ".sim2real.invalid"

    off_cfg = _set_ocsp(ctx, off_ca, False)
    assert off_cfg.get("Enabled") is False, (
        f"the control CA must observably report OCSP disabled before its issued bytes are "
        f"used as the absence baseline; Describe reports {off_cfg!r}"
    )
    on_cfg = _set_ocsp(ctx, on_ca, True, OcspCustomCname=custom_cname)
    assert on_cfg.get("Enabled") is True, (
        f"the OCSP CA must observably report OCSP enabled before its effect is graded; "
        f"Describe reports {on_cfg!r}"
    )
    assert on_cfg.get("OcspCustomCname") == custom_cname, (
        f"the custom responder CNAME must be observably stored before its appearance in the "
        f"issued certificate is graded: expected {custom_cname!r}, Describe reports "
        f"{on_cfg.get('OcspCustomCname')!r}"
    )

    # ONE CSR for both legs: any difference between the certificates is attributable to the
    # CA's OcspConfiguration and nothing else.
    csr_pem = _new_csr("ocsp.sim2real.invalid")
    off_leaf = _issue_leaf(ctx, off_ca, csr_pem)
    on_leaf = _issue_leaf(ctx, on_ca, csr_pem)

    # ---- Leg A: OCSP enabled -> an AIA OCSP accessDescription naming the custom responder ----
    on_uris = _ocsp_uris(on_leaf)
    assert on_uris, (
        f"with OcspConfiguration.Enabled=True the CA must place an OCSP responder URL in the "
        f"authorityInformationAccess extension of the certificates it issues: expected at "
        f"least one id-ad-ocsp URI containing {custom_cname!r}, the certificate carries "
        f"{on_uris!r} (all extension OIDs present: "
        f"{[e.oid.dotted_string for e in on_leaf.extensions]!r})"
    )
    joined = " ".join(on_uris)
    assert custom_cname in joined, (
        f"OcspCustomCname must decide the host of the AIA OCSP URI: expected the URI to "
        f"contain {custom_cname!r}, the issued certificate points at {on_uris!r}"
    )
    assert any(u.startswith("http://") or u.startswith("https://") for u in on_uris), (
        f"an OCSP accessLocation must be an http(s) URI a client can actually fetch; the "
        f"issued certificate carries {on_uris!r}"
    )

    # ---- Leg B: OCSP disabled -> no OCSP accessDescription, from the same CSR ----
    off_uris = _ocsp_uris(off_leaf)
    assert off_uris == [], (
        f"with OcspConfiguration.Enabled=False no OCSP responder may be advertised in the "
        f"issued certificate; it carries {off_uris!r}. The twin CA above proves an AIA OCSP "
        f"entry IS emitted on this wiring when OCSP is on, so this is the field taking effect "
        f"rather than a target that never emits AIA"
    )

    # ---- the twin closes ----
    assert set(on_uris) != set(off_uris), (
        f"the two CAs share a CSR and a run and differ only in OcspConfiguration, so their "
        f"issued AIA OCSP entries must differ: enabled={on_uris!r}, disabled={off_uris!r}"
    )
    assert on_leaf.serial_number != off_leaf.serial_number, (
        f"the two legs must be two distinct certificates, but both report serial "
        f"{off_leaf.serial_number:x}"
    )
    assert on_leaf.issuer != off_leaf.issuer, (
        f"the two legs were issued by two DIFFERENT CAs, so their issuers must differ; both "
        f"report {off_leaf.issuer.rfc4514_string()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
