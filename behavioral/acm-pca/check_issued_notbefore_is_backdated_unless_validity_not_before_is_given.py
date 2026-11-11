"""issued-notbefore-is-backdated-unless-validity-not-before-is-given."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "issued-notbefore-is-backdated-unless-validity-not-before-is-given"
GROUP = "representation"
SERVICES = ["acm-pca"]

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 3

# Documented in the IssueCertificate:Validity reference, not guessed.
_BACKDATE_S = 3600.0
# How much earlier than "now" leg B asks its notBefore to be. Deliberately NOT 3600, so that
# a target which ignores ValidityNotBefore and applies the default backdating produces a
# DIFFERENT answer than the one leg B demands.
_EXPLICIT_OFFSET_S = 1800.0
_SKEW_TOLERANCE_S = 120.0

_ACTIVATE_TIMEOUT_S = 180.0
_TEARDOWN_TIMEOUT_S = 420.0


# ===== CA lifecycle helpers (self-contained) =====


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
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED"."""
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + _TEARDOWN_TIMEOUT_S
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError:
            return
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
    """Create a ROOT CA and register its teardown AT CREATION TIME."""
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
    """GetCertificate, polling through RequestInProgressException until signing completes."""
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
    """Drive a PENDING_CERTIFICATE root CA to ACTIVE via the documented install sequence."""
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
        timeout_s=timeout_s, interval_s=2.0, description="CA reaching ACTIVE",
    )
    return ca_cert_pem


def _new_csr(common_name):
    """A locally generated RSA-2048 key and a PKCS#10 request for it."""
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


def _issue_and_parse(ctx, ca_arn, csr_pem, **extra):
    """Issue one leaf and return (parsed_certificate, t_before, t_after).

    The two timestamps bracket the issuance so that every clock assertion downstream is
    two-sided against instants this process actually observed.
    """
    from cryptography import x509

    pca = ctx.client("acm-pca")
    t_before = datetime.datetime.now(datetime.timezone.utc)
    cert_arn = pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr_pem.encode("ascii"),
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn=_END_ENTITY_TEMPLATE,
        Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
        **extra,
    )["CertificateArn"]
    pem, _ = _await_certificate(ctx, ca_arn, cert_arn, timeout_s=_ACTIVATE_TIMEOUT_S)
    t_after = datetime.datetime.now(datetime.timezone.utc)
    return x509.load_pem_x509_certificate(pem.encode("ascii")), t_before, t_after


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """IssueCertificate sets notBefore from the live clock: backdated by the documented 60 minutes
    when no ValidityNotBefore is given and exactly the requested instant when one is; notAfter
    follows the Validity argument relative to issuance (bounds bracket each call on both sides)."""
    _require_local_crypto()

    scenario = "acm-pca-notbefore-backdating"

    ca_arn = _create_ca(ctx, scenario)
    _activate_root_ca(ctx, ca_arn, timeout_s=_ACTIVATE_TIMEOUT_S)

    ca_status = _describe(ctx, ca_arn)["Status"]
    assert ca_status == "ACTIVE", (
        f"the CA must be ACTIVE before either leg is issued so that a refusal cannot be "
        f"blamed on CA state; DescribeCertificateAuthority reports {ca_status!r}"
    )

    # ONE CSR for both legs: anything that differs between the two certificates is
    # attributable to the ValidityNotBefore argument and nothing else.
    csr_pem = _new_csr("notbefore.sim2real.invalid")

    # ---- Leg A: no ValidityNotBefore -> the documented 60-minute backdating ----
    leaf_a, a_before, a_after = _issue_and_parse(ctx, ca_arn, csr_pem)
    nb_a = leaf_a.not_valid_before_utc
    lo = a_before - datetime.timedelta(seconds=_BACKDATE_S + _SKEW_TOLERANCE_S)
    hi = a_after - datetime.timedelta(seconds=_BACKDATE_S - _SKEW_TOLERANCE_S)
    assert lo <= nb_a <= hi, (
        f"with no ValidityNotBefore, notBefore must be the issuance instant minus "
        f"{_BACKDATE_S:.0f}s: IssueCertificate was called between {a_before} and {a_after}, so "
        f"notBefore must lie in [{lo}, {hi}], but the issued certificate carries {nb_a}"
    )
    assert nb_a < a_before, (
        f"the 60-minute rule backdates, so notBefore must be strictly BEFORE the moment "
        f"IssueCertificate was called: notBefore={nb_a}, call made at {a_before}"
    )

    # notAfter is derived from the Validity argument relative to issuance, not from notBefore.
    na_a = leaf_a.not_valid_after_utc
    na_lo = a_before + datetime.timedelta(days=_LEAF_DAYS, seconds=-_SKEW_TOLERANCE_S)
    na_hi = a_after + datetime.timedelta(days=_LEAF_DAYS, seconds=_SKEW_TOLERANCE_S)
    assert na_lo <= na_a <= na_hi, (
        f"Validity={{Value:{_LEAF_DAYS},Type:DAYS}} means notAfter is {_LEAF_DAYS} days after "
        f"issuance: the call was made between {a_before} and {a_after}, so notAfter must lie "
        f"in [{na_lo}, {na_hi}], but the issued certificate carries {na_a}"
    )

    # ---- Leg B: an explicit ABSOLUTE ValidityNotBefore must be honoured exactly ----
    requested_nb = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(seconds=_EXPLICIT_OFFSET_S)
    ).replace(microsecond=0)
    leaf_b, b_before, b_after = _issue_and_parse(
        ctx, ca_arn, csr_pem,
        ValidityNotBefore={"Value": int(requested_nb.timestamp()), "Type": "ABSOLUTE"},
    )
    nb_b = leaf_b.not_valid_before_utc
    drift_s = abs((nb_b - requested_nb).total_seconds())
    assert drift_s <= _SKEW_TOLERANCE_S, (
        f"an explicit ValidityNotBefore must be honoured: ABSOLUTE "
        f"{int(requested_nb.timestamp())} means {requested_nb}, but the issued certificate "
        f"carries notBefore={nb_b}, which is {drift_s:.0f}s away (tolerance "
        f"{_SKEW_TOLERANCE_S:.0f}s). A target that applied the default {_BACKDATE_S:.0f}s "
        f"backdating instead would land about "
        f"{abs(_BACKDATE_S - _EXPLICIT_OFFSET_S):.0f}s away"
    )

    # ---- the twin closes: the two legs asked for different starts and got different starts --
    # A target applying one fixed offset to every request cannot satisfy this.
    assert nb_b != nb_a, (
        f"leg A supplied no ValidityNotBefore and leg B supplied an explicit one "
        f"{_EXPLICIT_OFFSET_S:.0f}s in the past, so the two issued notBefore values must "
        f"differ; both are {nb_a}"
    )
    assert nb_b > nb_a, (
        f"leg B asked for a notBefore {_EXPLICIT_OFFSET_S:.0f}s in the past while leg A was "
        f"backdated {_BACKDATE_S:.0f}s, so leg B's notBefore must be the LATER of the two: "
        f"leg A={nb_a}, leg B={nb_b}"
    )
    assert leaf_b.serial_number != leaf_a.serial_number, (
        f"the two legs must be two distinct certificates, but both report serial "
        f"{leaf_a.serial_number:x} -- GetCertificate returned the same object twice"
    )
    assert leaf_b.issuer == leaf_a.issuer, (
        f"both legs must be signed by the same CA identity for the comparison above to mean "
        f"anything: {leaf_a.issuer.rfc4514_string()!r} vs {leaf_b.issuer.rfc4514_string()!r}"
    )
    assert b_before <= b_after, (
        f"the bracketing clock readings for leg B are inverted ({b_before} > {b_after}), so "
        f"no timing conclusion drawn from them would be sound"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
