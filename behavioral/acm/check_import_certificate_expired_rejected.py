"""import-certificate-expired-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-certificate-expired-rejected"
GROUP = 'overly-permissive'
SERVICES = ['acm']

# ===== helpers (self-contained) =====

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes (test-infra robustness, not a behavioral assertion)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


def _crypto():
    """Lazily import `cryptography`; ImportError propagates if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, ec, rsa, NameOID


def _mint(common_name, *, sans=None, not_before_days=1, days_valid=365, key="rsa2048"):
    """Mint a throwaway self-signed X.509 pair. Returns (cert_pem, key_pem, cert).

    `days_valid` may be NEGATIVE, which is how the already-expired certificate in
    this check is produced. The key is generated here and discarded with the
    process; it is NOT a credential.
    """
    x509, hashes, serialization, ec, rsa, NameOID = _crypto()
    if key == "ec256":
        pkey = ec.generate_private_key(ec.SECP256R1())
    else:
        bits = {"rsa512": 512, "rsa2048": 2048, "rsa4096": 4096}[key]
        pkey = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(pkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=not_before_days))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in (sans or [common_name])]),
            critical=False,
        )
        .sign(pkey, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem, cert


def _import(ctx, acm, cert_pem, key_pem, **kwargs):
    """ImportCertificate + teardown registered at creation time. Returns the ARN."""
    resp = _retry_throttle(
        lambda: acm.import_certificate(
            Certificate=cert_pem,
            PrivateKey=key_pem,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
            **kwargs,
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn


def _error_code(fn):
    """Call fn() and return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


# Every value of the modeled KeyAlgorithm enum. ListCertificates applies a DEFAULT
# keyTypes filter (the operation doc says RSA_2048 only; the Filters member doc says
# RSA_1024 + RSA_2048 -- the service model contradicts itself), so an
# effect-absent scan MUST pass keyTypes explicitly or it can miss a leaked
# certificate whose key type falls outside the default.
_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]


def _list_summaries(acm, **kwargs):
    """Return {arn: summary} across all ListCertificates pages, with the default
    keyTypes filter widened to the whole enum unless the caller overrides Includes."""
    kwargs.setdefault("Includes", {"keyTypes": list(_ALL_KEY_TYPES)})
    out = {}
    for page in acm.get_paginator("list_certificates").paginate(**kwargs):
        for c in page["CertificateSummaryList"]:
            out[c["CertificateArn"]] = c
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportCertificate refuses an already-expired certificate with ValidationException ("The
    certificate is expired...") and stores nothing, while the valid control import differing only in
    notAfter is accepted and stays listed (ListCertificates is polled, as it indexes eventually)."""
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-exp-").rstrip("-").lower() + ".example.com"
    control_domain = "control." + base
    expired_domain = "expired." + base

    # --- control: a valid pair imports and reaches ISSUED ---
    ok_cert, ok_key, ok_x509 = _mint(control_domain)
    control_arn = _import(ctx, acm, ok_cert, ok_key)
    control_desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=control_arn)["Certificate"],
        lambda d: d.get("Status") is not None and "Serial" in d,
        timeout_s=120,
        interval_s=3,
        description="control certificate published",
    )
    assert control_desc["Status"] == "ISSUED", control_desc["Status"]
    control_serial = control_desc["Serial"]

    # --- break exactly one thing: notBefore/notAfter both in the past ---
    bad_cert, bad_key, bad_x509 = _mint(
        expired_domain, not_before_days=400, days_valid=-30
    )
    assert bad_x509.not_valid_after < datetime.datetime.utcnow(), (
        "test setup error: the negative certificate is not actually expired"
    )
    code, message = _error_code(
        lambda: acm.import_certificate(Certificate=bad_cert, PrivateKey=bad_key)
    )
    assert code == "ValidationException", (
        f"an expired certificate must be refused at import with ValidationException, got {code!r}"
    )
    assert message == (
        "The certificate is expired. You can Import a certificate only during its "
        "validity period."
    ), f"the refusal must name expiry as the reason; got {message!r}"

    # --- the effect must be ABSENT: no certificate exists for that domain ---
    summaries = _list_summaries(acm)
    leaked = [
        a for a, s in summaries.items()
        if s.get("DomainName") == expired_domain
        or expired_domain in set(s.get("SubjectAlternativeNameSummaries") or ())
    ]
    assert not leaked, (
        f"the refused expired certificate was stored anyway: {leaked}"
    )
    # A refused import must also not have consumed the EXPIRED status bucket.
    expired_bucket = _list_summaries(acm, CertificateStatuses=["EXPIRED"])
    leaked_expired = [
        a for a, s in expired_bucket.items() if s.get("DomainName") == expired_domain
    ]
    assert not leaked_expired, (
        f"the refused certificate surfaced under CertificateStatuses=[EXPIRED]: {leaked_expired}"
    )

    # --- the control must be untouched ---
    after = acm.describe_certificate(CertificateArn=control_arn)["Certificate"]
    assert after["Status"] == "ISSUED", after["Status"]
    assert after["Serial"] == control_serial, (
        f"the refused import mutated the control certificate: "
        f"{control_serial!r} -> {after['Serial']!r}"
    )
    assert int(after["Serial"].replace(":", ""), 16) == ok_x509.serial_number, after["Serial"]
    # ListCertificates indexing is eventually consistent, so give it a bounded wait
    # (the assertion is still "the control IS listed" -- see the docstring).
    _poll_until(
        lambda: control_arn in _list_summaries(acm),
        lambda listed: listed,
        timeout_s=120,
        interval_s=5,
        description="the control certificate is still listed after the refused import",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
