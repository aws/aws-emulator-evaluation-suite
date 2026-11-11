"""import-certificate-unsupported-key-size-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-certificate-unsupported-key-size-rejected"
GROUP = 'overly-permissive'
SERVICES = ['acm']


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
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


_RSA_BITS = {"rsa1024": 1024, "rsa1536": 1536, "rsa2048": 2048, "rsa4096": 4096}


def _mint(common_name, *, key="rsa2048", days_valid=365):
    """Mint a throwaway self-signed pair at the requested RSA size; returns (cert_pem, key_pem, cert).
    1536 is the negative case: `cryptography` refuses moduli below 1024, ACM accepts RSA-1024, and
    1536 is the smallest size `cryptography` mints that ACM refuses."""
    x509, hashes, serialization, rsa, NameOID = _crypto()
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=_RSA_BITS[key])
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
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
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
        lambda: acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, **kwargs)
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# Every value of the modeled KeyAlgorithm enum. ListCertificates applies a narrow DEFAULT keyTypes
# filter (the model's docs disagree on whether it is RSA_2048 alone or RSA_1024 + RSA_2048), so an
# RSA-4096 certificate is INVISIBLE in a listing with `Includes` omitted. Passing `Includes={}`
# explicitly DISABLES the filter rather than falling back to the default, so it is the only
# spelling not gated by key algorithm at all -- which the leak scan needs, because `_ALL_KEY_TYPES`
# cannot name RSA_1536 (the size ACM refuses has no enum member).
_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]

# Passed as `Includes` to opt out of keyTypes filtering altogether. Named rather than inlined so the
# call sites read as a deliberate choice of channel and not as a forgotten argument.
_NO_KEY_TYPE_FILTER: dict = {}


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
    """ImportCertificate refuses a 1536-bit RSA key with ValidationException "ACM does not support
    this key type." and creates no certificate, while RSA-4096 is accepted with KeyAlgorithm
    RSA-4096 derived from the public key in the DER.
    """
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-keysize-").rstrip("-").lower() + ".example.com"
    big_domain = "rsa4096." + base
    small_domain = "rsa1536." + base

    # --- control / positive: the largest supported RSA size is accepted and derived ---
    big_cert, big_key, big_x509 = _mint(big_domain, key="rsa4096")
    big_arn = _import(ctx, acm, big_cert, big_key, Tags=[{"Key": "sim2real", "Value": CHECK}])
    big_desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=big_arn)["Certificate"],
        lambda d: d.get("KeyAlgorithm") is not None and "Serial" in d,
        timeout_s=120,
        interval_s=3,
        description="RSA-4096 certificate's derived fields published",
    )
    assert big_desc["Status"] == "ISSUED", big_desc["Status"]
    assert big_desc["KeyAlgorithm"] == "RSA-4096", (
        "KeyAlgorithm must be derived from the imported public key's modulus size; "
        f"got {big_desc['KeyAlgorithm']!r} for a 4096-bit key"
    )
    assert big_desc["SignatureAlgorithm"] == "SHA256WITHRSA", (
        f"SignatureAlgorithm={big_desc['SignatureAlgorithm']!r}"
    )
    assert big_desc["DomainName"] == big_domain, big_desc["DomainName"]
    big_serial = big_desc["Serial"]
    assert int(big_serial.replace(":", ""), 16) == big_x509.serial_number, big_serial

    # The list projection must carry the same derived algorithm.
    big_summary = _poll_until(
        lambda: _list_summaries(acm).get(big_arn),
        lambda s: s is not None and s.get("KeyAlgorithm") is not None,
        timeout_s=120,
        interval_s=5,
        description="RSA-4096 certificate indexed in ListCertificates",
    )
    assert big_summary["KeyAlgorithm"] == "RSA-4096", (
        f"ListCertificates KeyAlgorithm={big_summary['KeyAlgorithm']!r} disagrees with "
        "DescribeCertificate"
    )

    # --- break exactly one thing: an unsupported modulus size ---
    small_cert, small_key, _ = _mint(small_domain, key="rsa1536")
    code, message = _error_code(
        lambda: acm.import_certificate(Certificate=small_cert, PrivateKey=small_key)
    )
    # ValidationException is not among ImportCertificate's modelled errors, but it is what the
    # service returns; the assertion follows the service.
    assert code == "ValidationException", (
        "a 1536-bit RSA key is outside ACM's supported key algorithms and must be "
        f"refused with ValidationException, got {code!r}"
    )
    # The message is asserted too: 'ValidationException' alone is ACM's catch-all for
    # every certificate-material defect (expired cert, malformed PEM, key mismatch,
    # bad chain), so the code by itself does not establish that the *key algorithm*
    # is what was rejected.
    assert message == "ACM does not support this key type.", (
        "the refusal must name the key type as the reason; got " f"{message!r}"
    )

    # --- the effect must be ABSENT ---
    # `Includes=_NO_KEY_TYPE_FILTER`, NOT the widened enum the other call sites use, and NOT omitted.
    # RSA_1536 has no KeyAlgorithm enum member, so listing under `keyTypes=_ALL_KEY_TYPES` would
    # filter a leaked 1536-bit certificate straight out of the response and this assertion would
    # pass precisely when it must fail; omitting `Includes` applies the narrow default filter.
    summaries = _list_summaries(acm, Includes=_NO_KEY_TYPE_FILTER)
    leaked = [
        a for a, s in summaries.items()
        if s.get("DomainName") == small_domain
        or small_domain in set(s.get("SubjectAlternativeNameSummaries") or ())
    ]
    # The channel must be proven sighted BEFORE `not leaked` means anything: an empty or
    # over-filtered listing satisfies the absence assertion trivially. The RSA-4096 control is
    # itself outside ACM's narrow default keyTypes filter, so this fails if `Includes` is ever
    # dropped or re-narrowed.
    assert big_arn in summaries, (
        "the unfiltered listing cannot see the RSA-4096 control certificate, so it could not have "
        "seen a leaked 1536-bit one either -- the absence check below would be vacuous"
    )
    assert not leaked, f"the refused 1536-bit certificate was stored anyway: {leaked}"

    # --- the control must be untouched ---
    after = acm.describe_certificate(CertificateArn=big_arn)["Certificate"]
    assert after["Status"] == "ISSUED", after["Status"]
    assert after["KeyAlgorithm"] == "RSA-4096", after["KeyAlgorithm"]
    assert after["Serial"] == big_serial, (
        f"the refused import mutated the control: {big_serial!r} -> {after['Serial']!r}"
    )
    assert big_arn in _list_summaries(acm), "the control certificate disappeared"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
