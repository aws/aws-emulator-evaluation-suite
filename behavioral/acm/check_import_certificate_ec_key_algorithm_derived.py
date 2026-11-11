"""import-certificate-ec-key-algorithm-derived."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-certificate-ec-key-algorithm-derived"
GROUP = 'lifecycle'
SERVICES = ['acm']

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on ACM throttle codes."""
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
    """Lazily import `cryptography`; raises if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, ec, NameOID


def _mint_ec(common_name, *, curve="p256"):
    """Mint a throwaway self-signed EC pair. Returns (cert_pem, key_pem, cert).

    The key is generated in-process and discarded with it; it is NOT a credential.
    """
    x509, hashes, serialization, ec, NameOID = _crypto()
    if curve == "p256":
        pkey = ec.generate_private_key(ec.SECP256R1())
        algo = hashes.SHA256()
    elif curve == "p384":
        pkey = ec.generate_private_key(ec.SECP384R1())
        algo = hashes.SHA384()
    else:
        raise AssertionError(f"unsupported curve token {curve!r}")
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
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(pkey, algo)
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


# Every value of the modeled KeyAlgorithm enum. ListCertificates applies a default RSA-only
# keyTypes filter, so an EC certificate is invisible unless keyTypes is passed.
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """KeyAlgorithm and SignatureAlgorithm are derived from an imported EC key's curve: P-256 reports
    EC-prime256v1 / SHA256WITHECDSA and P-384 reports EC-secp384r1 / SHA384WITHECDSA, never RSA.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html
    """
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-ec-").rstrip("-").lower() + ".example.com"
    p256_domain = "p256." + base
    p384_domain = "p384." + base

    tags = [{"Key": "sim2real-purpose", "Value": "import-certificate-ec-key-algorithm-derived"}]

    p256_cert, p256_key, p256_x509 = _mint_ec(p256_domain, curve="p256")
    p256_arn = _import(ctx, acm, p256_cert, p256_key, Tags=tags)
    p384_cert, p384_key, p384_x509 = _mint_ec(p384_domain, curve="p384")
    p384_arn = _import(ctx, acm, p384_cert, p384_key, Tags=tags)

    p256 = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=p256_arn)["Certificate"],
        lambda d: d.get("KeyAlgorithm") is not None and "Serial" in d,
        timeout_s=120,
        interval_s=3,
        description="EC P-256 certificate's derived fields published",
    )
    p384 = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=p384_arn)["Certificate"],
        lambda d: d.get("KeyAlgorithm") is not None and "Serial" in d,
        timeout_s=120,
        interval_s=3,
        description="EC P-384 certificate's derived fields published",
    )

    for label, desc in (("P-256", p256), ("P-384", p384)):
        assert desc["Status"] == "ISSUED", f"{label}: {desc['Status']}"
        assert desc["Type"] == "IMPORTED", f"{label}: {desc['Type']}"
        assert not desc["KeyAlgorithm"].startswith("RSA"), (
            f"{label} EC certificate reported KeyAlgorithm={desc['KeyAlgorithm']!r}: the "
            "field is being echoed or hardcoded, not parsed from the public key"
        )
        assert "RSA" not in desc["SignatureAlgorithm"], (
            f"{label} EC certificate reported SignatureAlgorithm="
            f"{desc['SignatureAlgorithm']!r}"
        )

    # ACM spells secp256r1 by its OpenSSL alias but secp384r1 by its SECG name.
    assert p256["KeyAlgorithm"] == "EC-prime256v1", (
        f"secp256r1 must be reported as EC-prime256v1, got {p256['KeyAlgorithm']!r}"
    )
    assert p256["SignatureAlgorithm"] == "SHA256WITHECDSA", (
        f"got {p256['SignatureAlgorithm']!r}"
    )
    assert p384["KeyAlgorithm"] == "EC-secp384r1", (
        f"secp384r1 must be reported as EC-secp384r1, got {p384['KeyAlgorithm']!r}"
    )
    assert p384["SignatureAlgorithm"] == "SHA384WITHECDSA", (
        f"got {p384['SignatureAlgorithm']!r}"
    )

    assert p256["KeyAlgorithm"] != p384["KeyAlgorithm"], (
        "both curves reported the same KeyAlgorithm "
        f"({p256['KeyAlgorithm']!r}): the value is not curve-derived"
    )
    assert p256["SignatureAlgorithm"] != p384["SignatureAlgorithm"], (
        f"both curves reported the same SignatureAlgorithm ({p256['SignatureAlgorithm']!r})"
    )

    assert int(p256["Serial"].replace(":", ""), 16) == p256_x509.serial_number, p256["Serial"]
    assert int(p384["Serial"].replace(":", ""), 16) == p384_x509.serial_number, p384["Serial"]
    assert p256["DomainName"] == p256_domain, p256["DomainName"]
    assert p384["DomainName"] == p384_domain, p384["DomainName"]

    # _list_summaries passes keyTypes explicitly: the default filter excludes EC certificates.
    summaries = _poll_until(
        lambda: _list_summaries(acm),
        lambda s: p256_arn in s and p384_arn in s
        and s[p256_arn].get("KeyAlgorithm") is not None
        and s[p384_arn].get("KeyAlgorithm") is not None,
        timeout_s=120,
        interval_s=5,
        description="both EC certificates indexed in ListCertificates",
    )
    assert summaries[p256_arn]["KeyAlgorithm"] == "EC-prime256v1", (
        f"ListCertificates: {summaries[p256_arn]['KeyAlgorithm']!r}"
    )
    assert summaries[p384_arn]["KeyAlgorithm"] == "EC-secp384r1", (
        f"ListCertificates: {summaries[p384_arn]['KeyAlgorithm']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
