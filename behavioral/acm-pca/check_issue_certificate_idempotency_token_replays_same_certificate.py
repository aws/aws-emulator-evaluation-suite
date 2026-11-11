"""issue-certificate-idempotency-token-replays-same-certificate."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "issue-certificate-idempotency-token-replays-same-certificate"
GROUP = 'concurrency'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7
_ROOT_TEMPLATE = "arn:aws:acm-pca:::template/RootCACertificate/V1"
_END_ENTITY_TEMPLATE = "arn:aws:acm-pca:::template/EndEntityCertificate/V1"
_USAGE_MODE = "SHORT_LIVED_CERTIFICATE"
_LEAF_DAYS = 7
# IdempotencyToken is modeled length 1..36 in the acm-pca Smithy model; a 36-character token
# exercises the upper bound exactly.
_TOKEN_LEN = 36
# Enough concurrent callers that a lock-free "check then create" implementation is very likely
# to interleave, but few enough that a NON-idempotent service mints only 6 certificates
# (short-lived-certificate mode: $0.058 each) rather than a large bill.
_CONCURRENCY = 6


# ===== CA lifecycle helpers (self-contained) =====
# The teardown polls until it observes Status == "DELETED" (the transition that stops the
# meter); _create_ca tags the CA, whose only handle is a server-minted UUID.


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _require_local_crypto():
    """Decided BEFORE any create: an absent parser cannot be discovered after billing starts."""
    from cryptography import x509  # noqa: F401


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying, LOUD teardown that ends at an OBSERVED Status == "DELETED".

    The meter stops on the DELETED status, not on the delete call, and ctx.on_cleanup swallows
    whatever this raises -- so it polls for that status rather than assuming the call took.
    """
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 420
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
        f"Status=DELETED within 420s (last observed {last_status!r}). It is STILL BILLING. "
        f"Delete it manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, scenario, **overrides):
    """Create a CA and register its teardown AT CREATION TIME, before anything can assert."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
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
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _await_certificate(ctx, ca_arn, cert_arn, *, timeout_s):
    """GetCertificate, polling through RequestInProgressException until signing completes."""
    pca = ctx.client("acm-pca")

    def _probe():
        try:
            return pca.get_certificate(
                CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
            )
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
    certificate"): GetCertificateAuthorityCsr -> IssueCertificate with the RootCACertificate/V1
    template against the CA's OWN arn -> GetCertificate -> ImportCertificateAuthorityCertificate.
    """
    pca = ctx.client("acm-pca")
    _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )

    def _csr_probe():
        try:
            return pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn).get("Csr")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("RequestInProgressException", "InvalidStateException"):
                return None
            raise

    csr_pem = _poll_until(
        _csr_probe, lambda v: bool(v), timeout_s=timeout_s, interval_s=2.0,
        description="GetCertificateAuthorityCsr returning a CSR",
    )
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
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "ACTIVE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching ACTIVE after importing its own signed certificate",
    )
    return ca_cert_pem


def _new_key_and_csr(common_name):
    """A locally generated RSA-2048 key and ONE PKCS#10 request for it.

    Built exactly once, outside the executor: ACM-PCA's issuance idempotency is keyed on the
    token AND the request parameters, so a CSR regenerated per thread would differ by its
    signature bytes and collapse the check into a false failure.
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
    return key, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Concurrent IssueCertificate calls sharing one IdempotencyToken and one CSR collapse to
    exactly one certificate (one ARN, one serial), while a different token over the identical CSR
    mints a different certificate, so deduplication keys on the token and not the CSR."""
    _require_local_crypto()

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    pca = ctx.client("acm-pca")
    timeout_s = 240
    scenario = "acm-pca-issue-idempotency"

    ca_arn = _create_ca(ctx, scenario)
    _activate_root_ca(ctx, ca_arn, timeout_s=timeout_s)

    leaf_key, csr_pem = _new_key_and_csr("localhost")
    csr_bytes = csr_pem.encode("ascii")
    token = ctx.unique_name("i").replace("_", "-")[:_TOKEN_LEN].ljust(_TOKEN_LEN, "0")
    assert len(token) == _TOKEN_LEN, token

    def _issue(shared_token):
        # A botocore client is thread-safe for calls; it is created before the threads start.
        return pca.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr_bytes,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn=_END_ENTITY_TEMPLATE,
            Validity={"Value": _LEAF_DAYS, "Type": "DAYS"},
            IdempotencyToken=shared_token,
        )["CertificateArn"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        futures = [pool.submit(_issue, token) for _ in range(_CONCURRENCY)]
        arns, errors = [], []
        for fut in futures:
            try:
                arns.append(fut.result())
            except ClientError as exc:
                errors.append(exc.response.get("Error", {}).get("Code"))

    assert not errors, (
        f"{len(errors)} of {_CONCURRENCY} concurrent IssueCertificate calls sharing one "
        f"IdempotencyToken failed with {errors!r}; an idempotent replay must succeed, not race"
    )
    assert len(set(arns)) == 1, (
        f"{_CONCURRENCY} concurrent IssueCertificate calls with one IdempotencyToken and one "
        f"CSR produced {len(set(arns))} distinct certificate ARNs: {sorted(set(arns))!r} -- the "
        f"token was ignored and each retry signed and billed a new certificate"
    )
    replayed_arn = arns[0]

    serials = set()
    for arn in set(arns):
        pem, _ = _await_certificate(ctx, ca_arn, arn, timeout_s=timeout_s)
        serials.add(x509.load_pem_x509_certificate(pem.encode("ascii")).serial_number)
    assert len(serials) == 1, (
        f"one IdempotencyToken produced {len(serials)} distinct certificate serials: "
        f"{sorted(serials)!r}; the ARNs collapsed but the signed material did not"
    )
    replayed_serial = next(iter(serials))

    replayed_pem, _ = _await_certificate(ctx, ca_arn, replayed_arn, timeout_s=timeout_s)
    replayed = x509.load_pem_x509_certificate(replayed_pem.encode("ascii"))
    want_spki = leaf_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    got_spki = replayed.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert got_spki == want_spki, (
        "the collapsed certificate does not carry the public key of the CSR that was "
        f"submitted: got {got_spki[:24].hex()}..., expected {want_spki[:24].hex()}... -- the "
        "calls collapsed onto something that is not this request's certificate"
    )

    # ---- the control: a DIFFERENT token over the IDENTICAL CSR must NOT collapse ----
    other_token = ctx.unique_name("j").replace("_", "-")[:_TOKEN_LEN].ljust(_TOKEN_LEN, "0")
    assert other_token != token, (other_token, token)
    other_arn = _issue(other_token)
    other_pem, _ = _await_certificate(ctx, ca_arn, other_arn, timeout_s=timeout_s)
    other_serial = x509.load_pem_x509_certificate(other_pem.encode("ascii")).serial_number

    assert other_arn != replayed_arn, (
        f"a DIFFERENT IdempotencyToken over the identical CSR returned the SAME certificate "
        f"ARN {other_arn!r}; the deduplication is keyed on the request body rather than the "
        f"token, so the collapse asserted above proves nothing about the token"
    )
    assert other_serial != replayed_serial, (
        f"a DIFFERENT IdempotencyToken over the identical CSR returned the same serial "
        f"{other_serial!r}; ACM-PCA must sign a new certificate for a new token"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
