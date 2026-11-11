"""acm-reimport-into-an-amazon-issued-certificate-arn-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-reimport-into-an-amazon-issued-certificate-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['acm']

_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]

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


def _error_code(fn):
    """The AWS (code, message) raised by fn(), or a loud failure if it unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"the call was expected to be REFUSED but it succeeded, returning {result!r}"
    )


def _serial_int(text):
    """ACM's colon-grouped hex `Serial` as an integer. ACM renders zero-padded hex bytes (`0a:...`),
    which a string compare against `f"{n:x}"` misses whenever the leading byte is below 0x10."""
    return int(str(text).replace(":", ""), 16)


def _crypto():
    """Lazily import `cryptography`; ImportError propagates if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _subject(cn):
    """An X.509 Name. The CN is capped at 64 characters by RFC 5280 / `cryptography`."""
    x509, _h, _s, _r, NameOID = _crypto()
    assert len(cn) <= 64, f"CN {cn!r} is {len(cn)} chars; X.509 caps it at 64"
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])


def _pem(cert):
    _x, _h, serialization, _r, _n = _crypto()
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key):
    """PEM-serialise a key generated moments ago in this process. It is not a credential."""
    _x, _h, serialization, _r, _n = _crypto()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _rsa_key():
    _x, _h, _s, rsa, _n = _crypto()
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _root_ca(cn):
    """A self-signed RSA-2048 CA."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn))
        .issuer_name(_subject(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(cn, sans, issuer_cn, issuer_key):
    """A server certificate signed by `issuer_key`, with a DNS SAN list."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn))
        .issuer_name(_subject(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _summaries_for_domain(acm, domain):
    """Every certificate summary in the account whose DomainName is `domain`, fully paginated with
    a widened keyTypes filter, because the default filter is narrower than the enum."""
    out = []
    for page in acm.get_paginator("list_certificates").paginate(
            Includes={"keyTypes": list(_ALL_KEY_TYPES)}):
        for summary in page["CertificateSummaryList"]:
            if summary.get("DomainName") == domain:
                out.append(summary)
    return out


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "plane:control",
)
def run(ctx) -> None:
    """ImportCertificate into an AMAZON_ISSUED certificate ARN is refused with
    ResourceNotFoundException although the ARN exists, while the same payload re-imports into an
    IMPORTED ARN; the managed certificate keeps its type, status and lack of key material."""
    acm = ctx.client("acm")
    uid = ctx.unique_name("sim2real-behav-mgd-")
    managed_host = f"mgd-{uid}.example.com"
    imported_host = f"imp-{uid}.example.com"

    root, root_key = _root_ca(f"root-{uid}")
    payload_cert, payload_key = _leaf(imported_host, [imported_host], f"root-{uid}", root_key)

    # An ACM-MANAGED certificate. It never validates, which is exactly the state we want:
    # AMAZON_ISSUED, and holding key material only ACM can see.
    requested = _retry_throttle(lambda: acm.request_certificate(
        DomainName=managed_host, ValidationMethod="DNS",
        Tags=[{"Key": "sim2real", "Value": CHECK}]))
    managed_arn = requested["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=managed_arn), attempts=4, base_delay=3.0))

    # ACM fast-fails an example.com request to the terminal FAILED state within seconds, so the
    # check polls to it rather than racing PENDING_VALIDATION. DescribeCertificate can also omit
    # DomainName right after RequestCertificate, hence the second condition.
    managed_before = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=managed_arn)["Certificate"],
        lambda d: d.get("Status") == "FAILED" and "DomainName" in d,
        timeout_s=180, interval_s=5,
        description="the requested certificate settles into its terminal FAILED state",
    )
    assert managed_before["Type"] == "AMAZON_ISSUED", (
        f"RequestCertificate must produce an ACM-managed certificate; Type is "
        f"{managed_before['Type']!r}"
    )
    assert managed_before["FailureReason"] == "ADDITIONAL_VERIFICATION_REQUIRED", (
        "the terminal state must be reached for the documented reason -- ACM refuses to issue "
        f"for an example.com name; FailureReason is {managed_before['FailureReason']!r}"
    )
    assert managed_before["DomainName"] == managed_host, (
        f"the managed certificate's DomainName is {managed_before['DomainName']!r}, expected "
        f"{managed_host!r}"
    )
    assert managed_before.get("Serial") is None, (
        "an unvalidated managed certificate has no issued certificate and therefore no Serial; "
        f"got {managed_before.get('Serial')!r}"
    )

    # An IMPORTED certificate, the control target for the byte-identical call below.
    imported = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(payload_cert), PrivateKey=_key_pem(payload_key),
        CertificateChain=_pem(root), Tags=[{"Key": "sim2real", "Value": CHECK}]))
    imported_arn = imported["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=imported_arn), attempts=4, base_delay=3.0))
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=imported_arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED" and d.get("Type") == "IMPORTED",
        timeout_s=120, interval_s=3,
        description="the imported control certificate reaches ISSUED",
    )

    # (1) POSITIVE CONTROL FIRST, as the barrier: the very same payload re-imported into an
    #     IMPORTED ARN succeeds. So the refusal below cannot be blamed on the payload, on
    #     propagation, or on re-import being unsupported.
    replacement, replacement_key = _leaf(imported_host, [imported_host], f"root-{uid}", root_key)
    control = _retry_throttle(lambda: acm.import_certificate(
        CertificateArn=imported_arn, Certificate=_pem(replacement),
        PrivateKey=_key_pem(replacement_key), CertificateChain=_pem(root)))
    assert control["CertificateArn"] == imported_arn, (
        f"the control re-import must reuse the ARN; got {control['CertificateArn']!r}"
    )
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=imported_arn)["Certificate"],
        lambda d: d.get("Serial") and _serial_int(d["Serial"]) == replacement.serial_number,
        timeout_s=120, interval_s=3,
        description="the control re-import's serial becomes visible on the IMPORTED certificate",
    )

    # (2) Break exactly one thing: point the same operation at the AMAZON_ISSUED ARN.
    code, message = _error_code(lambda: acm.import_certificate(
        CertificateArn=managed_arn, Certificate=_pem(payload_cert),
        PrivateKey=_key_pem(payload_key), CertificateChain=_pem(root)))
    assert code == "ResourceNotFoundException", (
        "importing into an ACM-managed (AMAZON_ISSUED) certificate ARN must be refused with "
        f"'ResourceNotFoundException'; got {code!r}"
    )
    expected_message = f"The certificate ARN {managed_arn} is not an imported certificate ARN."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (3) EFFECT ABSENT: the managed certificate is untouched in every observable respect.
    managed_after = acm.describe_certificate(CertificateArn=managed_arn)["Certificate"]
    assert managed_after["Type"] == "AMAZON_ISSUED", (
        "the refused import must not have converted the managed certificate to IMPORTED; Type is "
        f"{managed_after['Type']!r}"
    )
    assert managed_after["Status"] == "FAILED", (
        f"Status after the refusal was {managed_after['Status']!r}, expected the terminal "
        "'FAILED' it held before -- a refused import must not restart the state machine"
    )
    assert managed_after["FailureReason"] == "ADDITIONAL_VERIFICATION_REQUIRED", (
        f"FailureReason after the refusal was {managed_after['FailureReason']!r}"
    )
    assert managed_after.get("Serial") is None, (
        "no certificate material may have been stored under the managed ARN; Serial is "
        f"{managed_after.get('Serial')!r} (the payload's serial is "
        f"{payload_cert.serial_number:x})"
    )
    assert managed_after["DomainName"] == managed_host, (
        f"the managed certificate's DomainName must be unchanged; got "
        f"{managed_after['DomainName']!r}, expected {managed_host!r} -- the payload names "
        f"{imported_host!r}"
    )
    assert managed_after["InUseBy"] == [], f"InUseBy became {managed_after['InUseBy']!r}"

    # (4) EFFECT ABSENT, no new resource: the refused call minted nothing under either name.
    #     ListCertificates is eventually consistent -- it can return 0 rows for a certificate
    #     DescribeCertificate already reports ISSUED -- so each count is taken only after the
    #     certificate we know exists has been observed in the listing.
    managed_summaries = _poll_until(
        lambda: _summaries_for_domain(acm, managed_host),
        lambda rows: any(r["CertificateArn"] == managed_arn for r in rows),
        timeout_s=180, interval_s=5,
        description="the managed certificate is indexed in ListCertificates",
    )
    assert len(managed_summaries) == 1, (
        f"exactly one certificate may carry {managed_host!r} after the refusal; the paginated "
        f"list holds {len(managed_summaries)}: {[s['CertificateArn'] for s in managed_summaries]!r}"
    )
    assert managed_summaries[0]["CertificateArn"] == managed_arn, (
        f"the single certificate for {managed_host!r} must be the one we requested; got "
        f"{managed_summaries[0]['CertificateArn']!r}"
    )
    imported_summaries = _poll_until(
        lambda: _summaries_for_domain(acm, imported_host),
        lambda rows: any(r["CertificateArn"] == imported_arn for r in rows),
        timeout_s=180, interval_s=5,
        description="the imported certificate is indexed in ListCertificates",
    )
    assert len(imported_summaries) == 1, (
        f"exactly one certificate may carry {imported_host!r}; the paginated list holds "
        f"{len(imported_summaries)}: {[s['CertificateArn'] for s in imported_summaries]!r}"
    )

    # (5) And the control target still holds what the control put there -- the refused call did
    #     not leak the payload into the neighbouring certificate either.
    imported_after = acm.describe_certificate(CertificateArn=imported_arn)["Certificate"]
    assert _serial_int(imported_after["Serial"]) == replacement.serial_number, (
        f"the IMPORTED certificate must still hold the control's serial "
        f"{replacement.serial_number:x}; got {imported_after['Serial']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
