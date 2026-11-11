"""import-certificate-chain-not-matching-leaf-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-certificate-chain-not-matching-leaf-rejected"
GROUP = 'overly-permissive'
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
    """Import `cryptography` lazily; ImportError propagates (never skips) if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _pem(obj):
    x509, hashes, serialization, rsa, NameOID = _crypto()
    return obj.public_bytes(serialization.Encoding.PEM)


def _pem_blocks(text):
    """Split a PEM bundle into its CERTIFICATE base64 bodies, in order.

    Comparing bodies ignores line wrapping and trailing newlines but keeps count and order.
    """
    blocks = []
    current = None
    for line in (text or "").replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if line == "-----BEGIN CERTIFICATE-----":
            current = []
        elif line == "-----END CERTIFICATE-----":
            assert current is not None, "END CERTIFICATE without a BEGIN"
            blocks.append("".join(current))
            current = None
        elif current is not None and line:
            current.append(line)
    assert current is None, "unterminated PEM block"
    return blocks


def _mint_ca(common_name):
    """Mint a throwaway self-signed CA; return (cert, private_key). Keys are not credentials."""
    x509, hashes, serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=800))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _mint_expired_ca(common_name):
    """Mint a throwaway self-signed CA whose validity window lies entirely in the past."""
    x509, hashes, serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now - datetime.timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _mint_leaf(common_name, ca_cert, ca_key):
    """Mint a leaf signed by (ca_cert, ca_key). Returns (cert, private_key)."""
    x509, hashes, serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def _key_pem(key):
    x509, hashes, serialization, rsa, NameOID = _crypto()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _import(ctx, acm, cert_pem, key_pem, **kwargs):
    """ImportCertificate with teardown registered; return the ARN."""
    kwargs.setdefault("Tags", [{"Key": "sim2real", "Value": CHECK}])
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
    """Call fn() and return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


# Every KeyAlgorithm value. ListCertificates applies a default keyTypes filter, so a scan
# for a leaked certificate must pass keyTypes explicitly.
_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]


def _list_summaries(acm, **kwargs):
    """Return {arn: summary} across all ListCertificates pages, over every key type by default."""
    kwargs.setdefault("Includes", {"keyTypes": list(_ALL_KEY_TYPES)})
    out = {}
    for page in acm.get_paginator("list_certificates").paginate(**kwargs):
        for c in page["CertificateSummaryList"]:
            out[c["CertificateArn"]] = c
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportCertificate accepts a chain that does not issue the leaf (returned verbatim, Issuer
    from the leaf) but refuses expired, malformed and non-certificate chains, each with its own
    ValidationException message, storing nothing; the control certificate stays intact.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_ImportCertificate.html
    """
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-chain-").rstrip("-").lower() + ".example.com"
    ca_a, ca_a_key = _mint_ca("sim2real-probe-acm-not-a-real-key CA A")
    ca_b, ca_b_key = _mint_ca("sim2real-probe-acm-not-a-real-key CA B")
    assert ca_a.subject != ca_b.subject, "test setup error: the two CAs are indistinguishable"

    # Control: leaf issued by CA-A, imported with CA-A as its chain.
    ok_domain = "ok." + base
    ok_leaf, ok_key = _mint_leaf(ok_domain, ca_a, ca_a_key)
    ok_arn = _import(ctx, acm, _pem(ok_leaf), _key_pem(ok_key), CertificateChain=_pem(ca_a))
    ok_desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=ok_arn)["Certificate"],
        lambda d: "Issuer" in d and d.get("Status") is not None,
        timeout_s=120,
        interval_s=3,
        description="chained control certificate published",
    )
    assert ok_desc["Status"] == "ISSUED", ok_desc["Status"]
    assert ok_desc["DomainName"] == ok_domain, ok_desc["DomainName"]
    assert "CA A" in ok_desc["Issuer"], (
        f"Issuer must be parsed from the leaf's issuer Name; got {ok_desc['Issuer']!r}"
    )
    assert ok_desc["Issuer"] != ok_desc["Subject"], (
        "a CA-issued leaf must not report itself as its own issuer: "
        f"Subject={ok_desc['Subject']!r} Issuer={ok_desc['Issuer']!r}"
    )
    got = _retry_throttle(lambda: acm.get_certificate(CertificateArn=ok_arn))
    assert "CertificateChain" in got, (
        f"GetCertificate must return the imported chain; keys={sorted(got)}"
    )
    assert _pem(ca_a).decode().strip() in got["CertificateChain"], (
        "the returned CertificateChain does not contain the CA that was imported"
    )

    # ACM does not verify that the chain issues the leaf: only the issuer linkage is wrong here,
    # and ACM stores and returns the chain as supplied.
    foreign_domain = "foreignca." + base
    foreign_leaf, foreign_key = _mint_leaf(foreign_domain, ca_a, ca_a_key)
    foreign_arn = _import(
        ctx, acm, _pem(foreign_leaf), _key_pem(foreign_key), CertificateChain=_pem(ca_b)
    )
    foreign_desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=foreign_arn)["Certificate"],
        lambda d: "Issuer" in d and d.get("Status") is not None,
        timeout_s=120,
        interval_s=3,
        description="the foreign-chain certificate published",
    )
    assert foreign_desc["Status"] == "ISSUED", (
        "a chain that does not issue the leaf is ACCEPTED by real ACM and reaches "
        f"ISSUED; got Status={foreign_desc['Status']!r}"
    )
    # Issuer is still parsed from the LEAF's DER, so it names CA-A even though CA-B is
    # what was stored as the chain: the two deliberately disagree.
    assert "CA A" in foreign_desc["Issuer"], (
        "Issuer must be parsed from the LEAF's issuer Name, not from the supplied "
        f"chain; got {foreign_desc['Issuer']!r} (the chain was CA B)"
    )
    assert "CA B" not in foreign_desc["Issuer"], (
        "Issuer must NOT be taken from the supplied CertificateChain; got "
        f"{foreign_desc['Issuer']!r}"
    )
    foreign_got = _retry_throttle(lambda: acm.get_certificate(CertificateArn=foreign_arn))
    assert _pem_blocks(foreign_got["CertificateChain"]) == _pem_blocks(
        _pem(ca_b).decode()
    ), (
        "the unrelated CA must be returned VERBATIM as the chain -- ACM neither "
        "rejects it, replaces it with the true issuer, nor drops it; got a "
        f"{len(_pem_blocks(foreign_got['CertificateChain']))}-certificate bundle "
        "that is not CA B"
    )

    # ACM validates the chain encoding and validity window; one defect per import.
    expired_ca, _expired_ca_key = _mint_expired_ca(
        "sim2real-probe-acm-not-a-real-key Expired CA"
    )
    rejections = (
        (
            "expiredchain",
            lambda: _pem(expired_ca),
            "A certificate in the chain is expired. You can Import a certificate "
            "only during its validity period.",
            "a chain member outside its validity window",
        ),
        (
            "malformedchain",
            lambda: b"-----BEGIN CERTIFICATE-----\nnot-base64!!!\n-----END CERTIFICATE-----\n",
            "The certificate chain is not PEM-encoded or is not valid.",
            "a chain that is not parseable PEM",
        ),
        (
            "keyaschain",
            lambda: _key_pem(ca_b_key),
            "Passed PEM is not a certificate chain.",
            "a well-formed PEM of the wrong type (a private key) as the chain",
        ),
    )
    for label, chain_bytes, expected_message, description in rejections:
        bad_domain = label + "." + base
        bad_leaf, bad_key = _mint_leaf(bad_domain, ca_a, ca_a_key)
        code, message = _error_code(
            lambda: acm.import_certificate(
                Certificate=_pem(bad_leaf),
                PrivateKey=_key_pem(bad_key),
                CertificateChain=chain_bytes(),
            )
        )
        assert code == "ValidationException", (
            f"{description} must be refused with ValidationException, got {code!r}"
        )
        # All certificate-material defects share ValidationException; only the message differs.
        assert message == expected_message, (
            f"{description} must be refused with its own specific reason; expected "
            f"{expected_message!r}, got {message!r}"
        )

        summaries = _list_summaries(acm)
        leaked = [
            a for a, s in summaries.items()
            if s.get("DomainName") == bad_domain
            or bad_domain in set(s.get("SubjectAlternativeNameSummaries") or ())
        ]
        assert not leaked, (
            f"the certificate refused for {description} was stored anyway: {leaked}"
        )

    after = acm.describe_certificate(CertificateArn=ok_arn)["Certificate"]
    assert after["Status"] == "ISSUED", after["Status"]
    assert after["Serial"] == ok_desc["Serial"], (
        f"the refused imports mutated the control: {ok_desc['Serial']!r} -> {after['Serial']!r}"
    )
    after_chain = _retry_throttle(lambda: acm.get_certificate(CertificateArn=ok_arn))
    assert after_chain["CertificateChain"] == got["CertificateChain"], (
        "a refused import replaced the control certificate's chain"
    )
    # ListCertificates indexing is eventually consistent.
    _poll_until(
        lambda: ok_arn in _list_summaries(acm),
        lambda listed: listed,
        timeout_s=120,
        interval_s=5,
        description="the control certificate is still listed after the refused imports",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
