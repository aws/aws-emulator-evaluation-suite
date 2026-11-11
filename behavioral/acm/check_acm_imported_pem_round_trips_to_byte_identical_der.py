"""acm-imported-pem-round-trips-to-byte-identical-der."""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-imported-pem-round-trips-to-byte-identical-der"
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


def _der(cert):
    _x, _h, serialization, _r, _n = _crypto()
    return cert.public_bytes(serialization.Encoding.DER)


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


def _leaf_mixed_sans(cn, sans, issuer_cn, issuer_key):
    """A leaf whose SAN extension mixes DNS names, a wildcard and an IP address.

    The SAN general-name TYPE is chosen by parsing each entry, so the caller's list is the single
    source of truth for what the DER carries.
    """
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    general = []
    for entry in sans:
        try:
            general.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            general.append(x509.DNSName(entry))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn))
        .issuer_name(_subject(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=364))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(general), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


@tags("axis:happy-path", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """The PEM ACM returns re-parses to DER byte-identical to the imported DER, and Serial,
    validity, Subject, DomainName and DNS SANs match those bytes; an IP SAN is stored
    in the DER but not listed in SubjectAlternativeNames.
    """
    acm = ctx.client("acm")
    uid = ctx.unique_name("sim2real-behav-der-")
    apex = f"{uid}.example.com"
    wildcard = f"*.{apex}"
    # 203.0.113.0/24 is TEST-NET-3 (RFC 5737): reserved for documentation, routed nowhere.
    ip_san = "203.0.113.7"
    sans = [apex, wildcard, ip_san]

    root, root_key = _root_ca(f"root-{uid}")
    leaf, leaf_key = _leaf_mixed_sans(apex, sans, f"root-{uid}", root_key)
    imported_der = _der(leaf)

    resp = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(leaf_key), CertificateChain=_pem(root),
        Tags=[{"Key": "sim2real", "Value": CHECK}]))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0))

    detail = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED" and "SubjectAlternativeNames" in d
        and d.get("Serial") and "NotBefore" in d and "NotAfter" in d,
        timeout_s=120, interval_s=3,
        description="the imported certificate's parsed X.509 fields are published",
    )
    served = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))["Certificate"]

    x509m, _h, _s, _r, _n = _crypto()
    reparsed = x509m.load_pem_x509_certificate(served.encode())
    round_tripped_der = _der(reparsed)

    # PEM -> ACM -> PEM -> DER is the DER that went in.
    assert round_tripped_der == imported_der, (
        "the certificate ACM returns must re-serialise to the DER that was imported, byte for "
        f"byte; imported {len(imported_der)} bytes sha256="
        f"{hashlib.sha256(imported_der).hexdigest()!r}, returned {len(round_tripped_der)} bytes "
        f"sha256={hashlib.sha256(round_tripped_der).hexdigest()!r}"
    )

    # ImportCertificate has no Serial parameter, so Serial must come from the DER.
    # Serial is lower-case colon-grouped hex; compare as an integer.
    assert int(detail["Serial"].replace(":", ""), 16) == leaf.serial_number, (
        f"Serial {detail['Serial']!r} does not decode to the imported serial "
        f"{leaf.serial_number:x}"
    )

    # The validity window is read out of the DER, to the second.
    for field, actual in (("NotBefore", leaf.not_valid_before_utc),
                          ("NotAfter", leaf.not_valid_after_utc)):
        reported = detail[field]
        skew = abs((reported - actual).total_seconds())
        assert skew < 1, (
            f"{field} is {reported.isoformat()!r} but the DER says {actual.isoformat()!r} "
            f"({skew}s apart); the value must come from the certificate"
        )

    # Compared sorted, since ACM's reporting order is not specified. A wildcard SAN is accepted on
    # import; the wildcard-position rule applies only to requested certificates.
    ext = reparsed.extensions.get_extension_for_class(x509m.SubjectAlternativeName).value
    # `get_values_for_type` yields the DECODED values -- `str` for DNSName and an
    # `ipaddress` object for IPAddress -- not GeneralName wrappers.
    der_names = ([str(n) for n in ext.get_values_for_type(x509m.DNSName)]
                 + [str(n) for n in ext.get_values_for_type(x509m.IPAddress)])
    assert sorted(der_names) == sorted(sans), (
        f"the round-tripped DER's SAN extension holds {sorted(der_names)!r}, but the imported "
        f"certificate encoded {sorted(sans)!r}"
    )
    der_ips = [str(n) for n in ext.get_values_for_type(x509m.IPAddress)]
    assert der_ips == [ip_san], (
        f"the round-tripped DER must still carry the IP general name; it carries {der_ips!r}"
    )
    assert sorted(detail["SubjectAlternativeNames"]) == sorted([apex, wildcard]), (
        "DescribeCertificate's SubjectAlternativeNames must be the DNS general names from the DER "
        f"-- including the wildcard; got {sorted(detail['SubjectAlternativeNames'])!r}, expected "
        f"{sorted([apex, wildcard])!r}"
    )
    # ACM stores the IP general name (it survives the DER round trip) but does not list it.
    assert ip_san not in detail["SubjectAlternativeNames"], (
        f"MEASURED: ACM does not project an IP general name into SubjectAlternativeNames, yet "
        f"{ip_san!r} appeared in {detail['SubjectAlternativeNames']!r}"
    )

    # Subject and DomainName are rendered from the DER Name, and DomainName is the first SAN.
    assert detail["Subject"].startswith(f"CN={apex}"), (
        f"Subject={detail['Subject']!r}, expected it to begin with 'CN={apex}'"
    )
    assert detail["DomainName"] == apex, (
        f"DomainName must be the first SAN entry {apex!r}; got {detail['DomainName']!r}"
    )
    # The chain is a separate field and does not contaminate the leaf.
    assert served.strip().count("BEGIN CERTIFICATE") == 1, (
        "GetCertificate's `Certificate` field must hold the leaf ALONE; it holds "
        f"{served.count('BEGIN CERTIFICATE')} certificates"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
