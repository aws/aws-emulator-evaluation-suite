"""validity-end-date-and-absolute-set-the-exact-notafter."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validity-end-date-and-absolute-set-the-exact-notafter"
GROUP = "representation"
SERVICES = ["acm-pca"]

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"

# Three distinct horizons, all inside the short-lived 7-day ceiling, deliberately ORDERED
# DAYS < END_DATE < ABSOLUTE so that the closing assertion can demand that ordering.
_DAYS_VALUE = 3
_END_DATE_DAYS = 4
_ABSOLUTE_DAYS = 5

# END_DATE and ABSOLUTE name an instant, not a span, so there is no issuance-latency slack.
_EXACT_TOLERANCE_S = 1.0
# The DAYS control is a span measured from issuance, so it needs the bracketing slack.
_SPAN_TOLERANCE_S = 120.0

_ACTIVATE_TIMEOUT_S = 180.0
_TEARDOWN_TIMEOUT_S = 420.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return it. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _require_local_crypto() -> None:
    """Fail before any CA is created if the local certificate parser is missing."""
    from cryptography import x509  # noqa: F401


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Disable, delete, and poll until the CA reports Status DELETED; raise if it never does.

    DeleteCertificateAuthority refuses an ACTIVE CA, so it is DISABLED first.
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
    """Create a tagged ROOT CA and register its teardown before anything asserts.

    The tag is how a stranded CA is found: its only handle is a server-minted UUID.
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

    Returns (certificate_pem, chain_pem_or_None).
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


def _issue_and_parse(ctx, ca_arn, csr_pem, validity):
    """Issue one leaf under `validity` and return (parsed_certificate, t_before, t_after)."""
    from cryptography import x509

    pca = ctx.client("acm-pca")
    t_before = datetime.datetime.now(datetime.timezone.utc)
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity=validity,
    )["CertificateArn"]
    pem, _ = _await_certificate(ctx, ca_arn, cert_arn, timeout_s=_ACTIVATE_TIMEOUT_S)
    t_after = datetime.datetime.now(datetime.timezone.utc)
    return x509.load_pem_x509_certificate(pem.encode("ascii")), t_before, t_after


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Validity.Type decides how Value is read: END_DATE (UTCTime YYMMDDHHMMSS) and ABSOLUTE (epoch
    seconds) set notAfter to that exact instant, DAYS spans from issuance (control), in that order.

    Reference: https://docs.aws.amazon.com/privateca/latest/APIReference/API_Validity.html
    """
    _require_local_crypto()

    scenario = "acm-pca-validity-type-arithmetic"

    ca_arn = _create_ca(ctx, scenario)
    _activate_root_ca(ctx, ca_arn, timeout_s=_ACTIVATE_TIMEOUT_S)

    ca_status = _describe(ctx, ca_arn)["Status"]
    assert ca_status == "ACTIVE", (
        f"the CA must be ACTIVE before any leg is issued so that a refusal cannot be blamed "
        f"on CA state; DescribeCertificateAuthority reports {ca_status!r}"
    )

    # ONE CSR for all three legs: anything that differs between the certificates is
    # attributable to the Validity argument and nothing else.
    csr_pem = _new_csr("validity-type.sim2real.invalid")

    now = datetime.datetime.now(datetime.timezone.utc)

    # ---- Leg 1: the DAYS control, on the same wiring, in the same run ----
    days_leaf, d_before, d_after = _issue_and_parse(
        ctx, ca_arn, csr_pem, {"Value": _DAYS_VALUE, "Type": "DAYS"}
    )
    days_na = days_leaf.not_valid_after_utc
    d_lo = d_before + datetime.timedelta(days=_DAYS_VALUE, seconds=-_SPAN_TOLERANCE_S)
    d_hi = d_after + datetime.timedelta(days=_DAYS_VALUE, seconds=_SPAN_TOLERANCE_S)
    assert d_lo <= days_na <= d_hi, (
        f"positive control: Validity={{Value:{_DAYS_VALUE},Type:DAYS}} means notAfter is "
        f"{_DAYS_VALUE} days after issuance. The call was made between {d_before} and "
        f"{d_after}, so notAfter must lie in [{d_lo}, {d_hi}], but the certificate carries "
        f"{days_na}. With this leg failing, nothing can be concluded from the two legs below"
    )

    # ---- Leg 2: END_DATE, spelled as a UTCTime YYMMDDHHMMSS integer (2-digit year < 2050) ----
    end_target = (now + datetime.timedelta(days=_END_DATE_DAYS)).replace(microsecond=0)
    end_value = int(end_target.strftime("%y%m%d%H%M%S"))
    end_leaf, _, _ = _issue_and_parse(
        ctx, ca_arn, csr_pem, {"Value": end_value, "Type": "END_DATE"}
    )
    end_na = end_leaf.not_valid_after_utc
    end_drift = abs((end_na - end_target).total_seconds())
    assert end_drift <= _EXACT_TOLERANCE_S, (
        f"Validity={{Value:{end_value},Type:END_DATE}} is the UTCTime stamp for {end_target} "
        f"and names an exact instant, not a span, so notAfter must equal it: the certificate "
        f"carries {end_na}, which is {end_drift:.0f}s away (tolerance "
        f"{_EXACT_TOLERANCE_S:.0f}s). A target reading Value as a day count would land about "
        f"{end_value / 365.0:.0f} years out"
    )

    # ---- Leg 3: ABSOLUTE, spelled as Unix epoch seconds ----
    abs_target = (now + datetime.timedelta(days=_ABSOLUTE_DAYS)).replace(microsecond=0)
    abs_value = int(abs_target.timestamp())
    abs_leaf, _, _ = _issue_and_parse(
        ctx, ca_arn, csr_pem, {"Value": abs_value, "Type": "ABSOLUTE"}
    )
    abs_na = abs_leaf.not_valid_after_utc
    abs_drift = abs((abs_na - abs_target).total_seconds())
    assert abs_drift <= _EXACT_TOLERANCE_S, (
        f"Validity={{Value:{abs_value},Type:ABSOLUTE}} is Unix epoch seconds for {abs_target} "
        f"and names an exact instant, so notAfter must equal it: the certificate carries "
        f"{abs_na}, which is {abs_drift:.0f}s away (tolerance {_EXACT_TOLERANCE_S:.0f}s)"
    )

    # ---- the same Value field, read three ways, must produce the requested ORDER ----
    # END_DATE and ABSOLUTE carry numerically enormous Values (~2.6e11 and ~1.8e9) while the
    # DAYS Value is 3. A target that ignores Type cannot produce this ordering.
    assert days_na < end_na < abs_na, (
        f"the three legs asked for horizons of {_DAYS_VALUE}, {_END_DATE_DAYS} and "
        f"{_ABSOLUTE_DAYS} days, so their notAfter values must come out in that order; got "
        f"DAYS={days_na}, END_DATE={end_na}, ABSOLUTE={abs_na}"
    )
    serials = {days_leaf.serial_number, end_leaf.serial_number, abs_leaf.serial_number}
    assert len(serials) == 3, (
        f"the three legs must be three distinct certificates, but only {len(serials)} distinct "
        f"serial(s) were returned: {sorted(f'{s:x}' for s in serials)!r}"
    )
    issuers = {days_leaf.issuer, end_leaf.issuer, abs_leaf.issuer}
    assert len(issuers) == 1, (
        f"all three legs must be signed by the same CA identity for the ordering assertion to "
        f"mean anything; got {[i.rfc4514_string() for i in issuers]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
