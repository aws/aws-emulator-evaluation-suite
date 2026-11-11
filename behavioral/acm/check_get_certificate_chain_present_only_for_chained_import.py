"""get-certificate-chain-present-only-for-chained-import."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-certificate-chain-present-only-for-chained-import"
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
    """Lazily import `cryptography`; ImportError propagates (never skips) if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _cert_pem(cert):
    x509, hashes, serialization, rsa, NameOID = _crypto()
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key):
    x509, hashes, serialization, rsa, NameOID = _crypto()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _name(common_name):
    x509, hashes, serialization, rsa, NameOID = _crypto()
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])


def _mint(common_name, *, issuer=None, ca=False, days_valid=365, san=None):
    """Mint one throwaway RSA-2048 certificate. Returns (cert, private_key).

    `issuer` is an (cert, key) pair; None means self-signed. All keys are generated
    in-process and discarded with it; none is a credential.
    """
    x509, hashes, serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _name(common_name)
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer[0].subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=None if ca else None), critical=True
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False
        )
    signing_key = issuer[1] if issuer else key
    return builder.sign(signing_key, hashes.SHA256()), key


def _import(ctx, acm, cert_pem, key_pem, **kwargs):
    """ImportCertificate + teardown registered at creation time. Returns the ARN."""
    resp = _retry_throttle(
        lambda: acm.import_certificate(
            Certificate=cert_pem, PrivateKey=key_pem,
            Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs,
        )
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn


def _pem_blocks(text):
    """Split a PEM bundle into its normalized CERTIFICATE blocks, in order."""
    blocks = []
    current = None
    for line in text.replace("\r\n", "\n").split("\n"):
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCertificate always returns CertificateChain, verbatim as imported: the leaf itself for an
    unchained import, the supplied CA for a 1-deep chain, and intermediate-then-root in submitted
    order for a 2-deep chain, never duplicating the leaf into its chain.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_GetCertificate.html
    """
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-getchain-").rstrip("-").lower() + ".example.com"

    root, root_key = _mint("sim2real-probe-acm-not-a-real-key Root", ca=True, days_valid=900)
    interm, interm_key = _mint(
        "sim2real-probe-acm-not-a-real-key Intermediate",
        issuer=(root, root_key),
        ca=True,
        days_valid=800,
    )

    # --- A. self-signed: no chain supplied ---
    a_domain = "nochain." + base
    a_cert, a_key = _mint(a_domain, san=[a_domain])
    a_arn = _import(ctx, acm, _cert_pem(a_cert), _key_pem(a_key))

    # --- B. one-deep chain ---
    b_domain = "chain1." + base
    b_cert, b_key = _mint(b_domain, issuer=(root, root_key), san=[b_domain])
    b_arn = _import(
        ctx, acm, _cert_pem(b_cert), _key_pem(b_key), CertificateChain=_cert_pem(root)
    )

    # --- C. two-deep chain, intermediate first ---
    c_domain = "chain2." + base
    c_cert, c_key = _mint(c_domain, issuer=(interm, interm_key), san=[c_domain])
    c_bundle = _cert_pem(interm) + _cert_pem(root)
    c_arn = _import(ctx, acm, _cert_pem(c_cert), _key_pem(c_key), CertificateChain=c_bundle)

    def _get(arn):
        return _poll_until(
            lambda: _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn)),
            lambda r: "Certificate" in r,
            timeout_s=120,
            interval_s=3,
            description=f"GetCertificate body available for {arn}",
        )

    a_got, b_got, c_got = _get(a_arn), _get(b_arn), _get(c_arn)

    # (A) For an import with no chain ACM synthesizes one: a single-certificate bundle
    #     that is the leaf itself, not omitted, null or "".
    assert "CertificateChain" in a_got, (
        "GetCertificate must return CertificateChain even for an import that supplied "
        f"no chain (ACM synthesizes the leaf as its own chain); keys={sorted(a_got)}"
    )
    a_chain = _pem_blocks(a_got["CertificateChain"])
    assert len(a_chain) == 1, (
        "an unchained import's synthesized chain is exactly one certificate, got "
        f"{len(a_chain)}"
    )
    assert _pem_blocks(a_got["Certificate"]) == [
        _pem_blocks(_cert_pem(a_cert).decode())[0]
    ], "GetCertificate returned a different leaf than the one imported (case A)"
    assert a_chain == _pem_blocks(a_got["Certificate"]), (
        "for a self-signed import with no chain supplied, CertificateChain must be "
        "the leaf itself, not a different or empty certificate; got a "
        f"{len(a_chain)}-certificate bundle that differs from the leaf"
    )

    # (B) Present, exactly one, and it is the CA that was supplied.
    assert "CertificateChain" in b_got, (
        f"a chained import must return CertificateChain; keys={sorted(b_got)}"
    )
    b_chain = _pem_blocks(b_got["CertificateChain"])
    assert b_chain == _pem_blocks(_cert_pem(root).decode()), (
        f"the 1-deep chain must be exactly the imported root; got {len(b_chain)} "
        "certificate(s) that do not match"
    )
    assert _pem_blocks(b_got["Certificate"]) == _pem_blocks(_cert_pem(b_cert).decode()), (
        "GetCertificate returned a different leaf than the one imported (case B)"
    )
    # The leaf must not be duplicated into its own chain.
    assert _pem_blocks(b_got["Certificate"])[0] not in b_chain, (
        "the leaf certificate was echoed back inside CertificateChain"
    )

    # (C) Two certificates, in the submitted order: ACM stores the chain verbatim and
    #     does not re-sort it. Bodies are compared normalized, since PEM wrapping is not contract.
    c_chain = _pem_blocks(c_got["CertificateChain"])
    assert len(c_chain) == 2, (
        f"a 2-deep chain must return exactly 2 certificates, got {len(c_chain)}"
    )
    assert c_chain == _pem_blocks(c_bundle.decode()), (
        "the 2-deep chain must be returned in the submitted intermediate-then-root "
        f"order; got a bundle of {len(c_chain)} in a different order or content"
    )
    assert c_chain[0] != c_chain[1], "the chain contains the same certificate twice"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
