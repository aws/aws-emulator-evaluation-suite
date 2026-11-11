"""import-certificate-san-extension-parsed-from-der."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-certificate-san-extension-parsed-from-der"
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


def _mint(common_name, *, sans=None, days_valid=365, not_before_days=1, key="rsa2048"):
    """Mint a throwaway self-signed X.509 pair. Returns (cert_pem, key_pem, cert).
    The key is not a credential; subjects carry a marker so the artifact is obviously synthetic."""
    x509, hashes, serialization, ec, rsa, NameOID = _crypto()
    if key == "ec256":
        pkey = ec.generate_private_key(ec.SECP256R1())
        algo = hashes.SHA256()
    else:
        bits = {"rsa512": 512, "rsa2048": 2048, "rsa4096": 4096}[key]
        pkey = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        algo = hashes.SHA256()
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


# Every value of the modeled KeyAlgorithm enum. ListCertificates applies a DEFAULT keyTypes
# filter (the model's docs disagree on whether it is RSA_2048 alone or RSA_1024 + RSA_2048),
# so any scan that must be exhaustive has to pass keyTypes explicitly.
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
    """DescribeCertificate's identity fields (SANs in DER order, DomainName, Serial, Subject, Issuer,
    algorithms, validity, key-usage sentinels) are parsed from the imported DER, not echoed; the
    list projection caps SANs at 100 and sets HasAdditionalSubjectAlternativeNames only when cut.
    """
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-der-").rstrip("-").lower() + ".example.com"
    apex = base
    alt_a = "alt-a." + base
    alt_b = "alt-b." + base

    cert_pem, key_pem, cert = _mint(apex, sans=[apex, alt_a, alt_b])
    arn = _import(ctx, acm, cert_pem, key_pem)

    desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: "SubjectAlternativeNames" in d and "Serial" in d,
        timeout_s=120,
        interval_s=3,
        description="imported certificate's parsed X.509 fields published",
    )

    # (1) The SAN LIST comes from the extension -- alt_a/alt_b were never in a request
    #     field -- and it preserves DER order, so this is a list equality. Order is
    #     contractual: DomainName is defined as the first entry (see (2)).
    assert desc["SubjectAlternativeNames"] == [apex, alt_a, alt_b], (
        "SubjectAlternativeNames must be parsed from the DER SAN extension, in DER "
        f"order; expected {[apex, alt_a, alt_b]}, got {desc['SubjectAlternativeNames']}"
    )
    # (2) DomainName is derived, and is the FIRST SAN entry / the CN -- not a request field.
    assert desc["DomainName"] == apex, f"DomainName={desc['DomainName']!r} expected {apex!r}"

    # (3) Serial is the DER serial, rendered as colon-separated hex.
    serial_txt = desc["Serial"]
    assert ":" in serial_txt, f"Serial must be colon-grouped hex, got {serial_txt!r}"
    assert int(serial_txt.replace(":", ""), 16) == cert.serial_number, (
        f"Serial {serial_txt!r} does not decode to the imported certificate's "
        f"serial {cert.serial_number}"
    )

    # (4) Subject / Issuer are rendered from the DER Name (self-signed => equal CN).
    #     The two are rendered DIFFERENTLY: `Subject` is the full RFC-2253-style name
    #     ("CN=<apex>,OU=sim2real-probe-acm-not-a-real-key") while `Issuer` is the bare
    #     CN value ("<apex>") with no "CN=" prefix and no OU.
    assert desc["Subject"].startswith(f"CN={apex}"), f"Subject={desc['Subject']!r}"
    assert desc["Issuer"] == apex, (
        "a self-signed import must be its own issuer, reported as the bare issuer CN "
        f"(not a full DN); Issuer={desc['Issuer']!r} expected {apex!r}"
    )

    # (5) Algorithm fields are derived from the key and the signature, not requested.
    assert desc["KeyAlgorithm"] == "RSA-2048", f"KeyAlgorithm={desc['KeyAlgorithm']!r}"
    assert desc["SignatureAlgorithm"] == "SHA256WITHRSA", (
        f"SignatureAlgorithm={desc['SignatureAlgorithm']!r}"
    )

    # (6) Validity window comes from the DER, to the second.
    not_after = desc["NotAfter"]
    expected_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    skew = abs((not_after - expected_after).total_seconds())
    assert skew < 2, f"NotAfter {not_after} differs from the DER notAfter {expected_after}"

    # (7) Import-specific derived state.
    assert desc["Type"] == "IMPORTED", desc["Type"]
    assert desc["Status"] == "ISSUED", desc["Status"]
    # KeyUsages / ExtendedKeyUsages are read from extensions this certificate does NOT
    # carry (`_mint` adds only SubjectAlternativeName), so ACM reports the "no such
    # extension" sentinels: KeyUsages [{'Name': 'ANY'}] and ExtendedKeyUsages
    # [{'Name': 'NONE', 'OID': ''}] -- spelled differently, and the EKU entry carries an
    # EMPTY OID string rather than omitting the key.
    assert desc["KeyUsages"] == [{"Name": "ANY"}], (
        "a certificate with no keyUsage extension must report the ANY sentinel; got "
        f"{desc.get('KeyUsages')!r}"
    )
    assert desc["ExtendedKeyUsages"] == [{"Name": "NONE", "OID": ""}], (
        "a certificate with no extendedKeyUsage extension must report the NONE "
        f"sentinel with an empty OID; got {desc.get('ExtendedKeyUsages')!r}"
    )
    assert desc["RenewalEligibility"] == "INELIGIBLE", desc.get("RenewalEligibility")
    assert desc["InUseBy"] == [], f"a freshly imported cert is attached to nothing: {desc['InUseBy']}"
    assert "RenewalSummary" not in desc, (
        f"an imported cert has no managed-renewal summary: {desc.get('RenewalSummary')}"
    )

    # (8) The list projection must report the extra names, not just the apex, and
    #     `HasAdditionalSubjectAlternativeNames` is a TRUNCATION flag, not a "more than one
    #     name" flag: ListCertificates returns at most the FIRST 100 names in
    #     `SubjectAlternativeNameSummaries`, and the flag is True only when it cut the list.
    #     Both sides of the flag are exercised below, so neither constant passes.
    summary = _poll_until(
        lambda: _list_summaries(acm).get(arn),
        lambda s: s is not None and "HasAdditionalSubjectAlternativeNames" in s,
        timeout_s=120,
        interval_s=5,
        description="certificate indexed in ListCertificates",
    )
    assert summary["HasAdditionalSubjectAlternativeNames"] is False, (
        "a 3-name certificate fits well inside the 100-name page, so the truncation "
        "flag must be False; got "
        f"{summary.get('HasAdditionalSubjectAlternativeNames')!r}"
    )
    assert summary["SubjectAlternativeNameSummaries"] == [apex, alt_a, alt_b], (
        "the list projection must carry every name from the DER SAN extension in DER "
        f"order, not just the apex; got {summary.get('SubjectAlternativeNameSummaries')}"
    )

    # (9) The truncating side: a 101-name certificate. ACM accepts it, DescribeCertificate
    #     returns all 101 names, ListCertificates returns exactly the first 100, and the
    #     flag flips to True.
    many_apex = ctx.unique_name("sim2real-behav-der-many-").rstrip("-").lower() + ".example.com"
    many_names = [many_apex] + [f"n{i}.{many_apex}" for i in range(1, 101)]
    assert len(many_names) == 101, len(many_names)
    many_pem, many_key, _many_cert = _mint(many_apex, sans=many_names)
    many_arn = _import(ctx, acm, many_pem, many_key)
    many_desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=many_arn)["Certificate"],
        lambda d: d.get("SubjectAlternativeNames") is not None,
        timeout_s=120,
        interval_s=3,
        description="the 101-name certificate's parsed SAN list published",
    )
    assert many_desc["SubjectAlternativeNames"] == many_names, (
        "DescribeCertificate must return the FULL SAN list -- it is the documented "
        f"escape hatch from the list projection's 100-name cap; got "
        f"{len(many_desc.get('SubjectAlternativeNames') or [])} name(s)"
    )
    many_summary = _poll_until(
        lambda: _list_summaries(acm).get(many_arn),
        lambda s: s is not None and "HasAdditionalSubjectAlternativeNames" in s,
        timeout_s=180,
        interval_s=5,
        description="the 101-name certificate indexed in ListCertificates",
    )
    assert many_summary["HasAdditionalSubjectAlternativeNames"] is True, (
        "a 101-name certificate exceeds the list projection's 100-name page, so the "
        "truncation flag must be True; got "
        f"{many_summary.get('HasAdditionalSubjectAlternativeNames')!r}"
    )
    assert many_summary["SubjectAlternativeNameSummaries"] == many_names[:100], (
        "ListCertificates must return exactly the FIRST 100 names in DER order (not a "
        f"different 100, not all 101); got "
        f"{len(many_summary.get('SubjectAlternativeNameSummaries') or [])} name(s)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
