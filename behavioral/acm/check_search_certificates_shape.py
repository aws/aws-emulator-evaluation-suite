"""search-certificates-shape."""
from __future__ import annotations

import datetime
import time
from behavioral_harness import tags
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CHECK = "search-certificates-shape"
GROUP = 'lifecycle'
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

def _self_signed_cert(common_name, days_valid=365, key_size=2048, san_names=None):
    """Generate a self-signed cert/key pair for ImportCertificate. Returns (cert_pem, key_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    sans = san_names if san_names else [common_name]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem

def _import_cert(ctx, acm, domain=None, **kwargs):
    """Generate a self-signed cert and import it. Returns (arn, cert_pem, key_pem)."""
    domain = domain or ctx.unique_name("sim2real-behav-imported-").rstrip("-") + ".example.com"
    cert_pem, key_pem = _self_signed_cert(domain)
    kwargs.setdefault("Tags", [{"Key": "sim2real-purpose", "Value": "search-certificates-shape"}])
    resp = _retry_throttle(
        lambda: acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, **kwargs)
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, cert_pem, key_pem

def _find_unfiltered(acm, arn, timeout_s=90.0, interval_s=3.0):
    """Poll unfiltered, paginated SearchCertificates until arn is visible.

    Returns (its entry, the full set of entries seen on the pass that found it).
    """
    deadline = time.monotonic() + timeout_s
    last_seen: dict[str, dict] = {}
    while time.monotonic() < deadline:
        last_seen = {}
        next_token = None
        for _ in range(50):  # bounded pagination
            kwargs = {"MaxResults": 200}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = _retry_throttle(lambda: acm.search_certificates(**kwargs))
            assert "Results" in resp, sorted(resp.keys())
            results = resp["Results"]
            assert isinstance(results, list), type(results)
            for entry in results:
                assert "CertificateArn" in entry, entry
                assert entry["CertificateArn"].startswith("arn:"), entry["CertificateArn"]
                last_seen[entry["CertificateArn"]] = entry
            next_token = resp.get("NextToken")
            if arn in last_seen or not next_token:
                break
        if arn in last_seen:
            return last_seen[arn], last_seen
        time.sleep(interval_s)
    raise AssertionError(f"{arn} never appeared in unfiltered SearchCertificates within {timeout_s}s")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchCertificates returns a just-imported certificate as a CertificateSearchResult: no
    top-level DomainName, AcmCertificateMetadata with Type IMPORTED, and non-empty X509Attributes."""
    acm = ctx.client("acm")
    if not hasattr(acm, "search_certificates"):
        raise AssertionError("SearchCertificates not present in the installed botocore model")

    arn, _cert_pem, _key_pem = _import_cert(ctx, acm)

    entry, _all_seen = _find_unfiltered(acm, arn)

    # CertificateSearchResult is a distinct shape from CertificateSummary (ListCertificates) and
    # from CertificateDetail (DescribeCertificate): Status/Type live one level down inside
    # CertificateMetadata.AcmCertificateMetadata, and there is no top-level DomainName field.
    assert "DomainName" not in entry, entry
    acm_meta = entry.get("CertificateMetadata", {}).get("AcmCertificateMetadata")
    assert acm_meta is not None, entry
    assert acm_meta.get("Type") == "IMPORTED", acm_meta
    x509_attrs = entry.get("X509Attributes")
    assert isinstance(x509_attrs, dict) and x509_attrs, entry


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
