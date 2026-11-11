"""op-contract-import-certificate."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "op-contract-import-certificate"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportCertificate creates an ISSUED, Type=IMPORTED certificate immediately
    (no validation needed); importing a Certificate blob that cannot even be
    base64-decoded is rejected with ValidationException."""
    acm = ctx.client("acm")
    domain = _domain(ctx)
    cert_pem, key_pem = _generate_self_signed_cert(domain)

    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-purpose", "Value": "import-contract"}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))
    assert arn.startswith(f"arn:aws:acm:{ctx.region}:"), arn
    assert ":certificate/" in arn, arn

    detail = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert detail["Type"] == "IMPORTED", detail["Type"]
    assert detail["Status"] == "ISSUED", detail["Status"]
    assert detail["DomainName"] == domain, detail["DomainName"]

    # error boundary: ACM only supports RSA keys of exactly 1024/2048/3072/4096
    # bits, or EC keys on the P-256/P-384/P-521 curves, for imported
    # certificates. On real AWS, an odd-but-still-1024..4096-bit RSA key
    # (e.g. 1536 bits) is accepted rather than rejected, and an EC key on an
    # unsupported curve (e.g. P-224/SECP224R1) is *also* accepted rather than
    # rejected -- ACM's enforcement for imported certificates is looser than
    # the docs imply for both key families. Even a key size below the
    # documented RSA floor (e.g. a hand-assembled 512-bit RSA key) turns out
    # NOT to be a reliable error boundary either -- real ACM accepts it too.
    # (Note: ACM does not verify that a supplied PrivateKey cryptographically
    # corresponds to the supplied Certificate's public key at import time, so
    # a mismatched-but-otherwise valid key pair is *not* a reliable error
    # boundary here either.) What IS reliably enforced is that the supplied
    # Certificate must actually be decodable as base64: merely *shortening*
    # a body line (while leaving every character valid base64) turns out NOT
    # to be a reliable error boundary either -- ACM's certificate parser is
    # lenient enough to tolerate that. Injecting an actual non-base64
    # character into the body (while keeping the BEGIN/END framing intact),
    # so the blob can no longer be base64-decoded at all, reliably triggers
    # a rejection -- on real AWS this is surfaced as ValidationException
    # (the request-shape/blob-format validation layer), not
    # InvalidParameterException (which is reserved for structurally-decodable
    # but semantically-invalid certificate content).
    garbled_cert_pem = _corrupt_pem_body(cert_pem)
    code, message = _error(
        lambda: acm.import_certificate(Certificate=garbled_cert_pem, PrivateKey=key_pem)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "The certificate is not PEM-encoded or is not valid."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


    # confirm the failed reimport created nothing new. list_certificates is a
    # separate, eventually-consistent index from describe_certificate (which
    # already confirmed the real cert above), and it can require pagination
    # to reach an arbitrarily-ordered account's full certificate set, so poll
    # a fully-paginated scan for the (unique, ctx-generated) domain rather
    # than assuming the freshly-imported cert is visible on the first page of
    # a single, unpolled call.
    def _find_matching():
        matches = []
        paginator = acm.get_paginator("list_certificates")
        for page in paginator.paginate():
            for c in page["CertificateSummaryList"]:
                if c["DomainName"] == domain:
                    matches.append(c)
        return matches

    matching = _poll_until(
        _find_matching,
        lambda matches: len(matches) >= 1,
        description=f"imported certificate for {domain} indexed in ListCertificates",
    )
    assert len(matching) == 1 and matching[0]["CertificateArn"] == arn, (
        f"expected exactly [{arn}] matching domain {domain} in ListCertificates, got {matching!r}"
    )


def _poll_until(fetch, predicate, timeout_s: float = 60.0, interval_s: float = 2.0, description: str = "condition"):
    import time

    deadline = time.monotonic() + timeout_s
    result = fetch()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {result!r}")
        time.sleep(interval_s)
        result = fetch()
    return result


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _domain(ctx) -> str:
    return f"{ctx.unique_name('sim2real-acm-')}.example.com".lower()


def _corrupt_pem_body(pem_bytes: bytes) -> bytes:
    """Inject a character that is not part of the base64 alphabet into a body
    line of a PEM blob, leaving the ``-----BEGIN/END-----`` framing lines
    untouched, so the result still LOOKS like PEM but can no longer be
    base64-decoded at all (merely *shortening* a body line, while keeping
    every remaining character valid base64, is tolerated by ACM's lenient
    certificate parser and is therefore not a reliable error boundary)."""
    lines = pem_bytes.decode("ascii").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("-----BEGIN") or line.startswith("-----END") or not line.strip():
            continue
        mid = len(line) // 2
        # "!" is not a valid base64 character, so this guarantees the whole
        # blob fails to base64-decode, regardless of decoder leniency.
        lines[i] = line[:mid] + "!" + line[mid + 1 :]
        break
    return ("\n".join(lines) + "\n").encode("ascii")


def _generate_self_signed_cert(common_name: str, key_size: int = 2048):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
