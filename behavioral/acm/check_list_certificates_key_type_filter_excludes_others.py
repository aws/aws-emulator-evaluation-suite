"""list-certificates-key-type-filter-excludes-others."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-certificates-key-type-filter-excludes-others"
GROUP = 'overly-permissive'
SERVICES = ['acm']


_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

# Every value of the modeled KeyAlgorithm enum.
_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]


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


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=5.0, description="condition"):
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
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    return x509, hashes, serialization, ec, rsa, NameOID, ExtendedKeyUsageOID


def _mint(common_name, *, key="rsa2048", server_auth_eku=False):
    """Mint a throwaway self-signed pair. Returns (cert_pem, key_pem).

    Keys are generated in-process and discarded with it; none is a credential.

    `server_auth_eku` adds an extendedKeyUsage extension with TLS web server
    authentication, which is what the `Includes.extendedKeyUsage` filter case below
    partitions on. Without it the certificate carries NO EKU extension and real ACM
    reports the `NONE` sentinel for it.
    """
    x509, hashes, serialization, ec, rsa, NameOID, ExtendedKeyUsageOID = _crypto()
    if key == "ec256":
        pkey = ec.generate_private_key(ec.SECP256R1())
        algo = hashes.SHA256()
    else:
        pkey = rsa.generate_private_key(
            public_exponent=65537, key_size={"rsa2048": 2048, "rsa4096": 4096}[key]
        )
        algo = hashes.SHA256()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-probe-acm-not-a-real-key"),
    ])
    now = datetime.datetime.utcnow()
    builder = (
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
    )
    if server_auth_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    cert = builder.sign(pkey, algo)
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


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


def _arns(acm, **kwargs):
    """Return the set of ARNs ListCertificates returns for exactly these arguments.

    No Includes default is injected here: which filter is applied is the subject of
    this check, so every call states its own.
    """
    out = set()
    for page in acm.get_paginator("list_certificates").paginate(**kwargs):
        for c in page["CertificateSummaryList"]:
            out.add(c["CertificateArn"])
    return out


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Includes.keyTypes and Includes.extendedKeyUsage must return only matching certificates and
    exclude every other one, and the default filter must exclude RSA-4096 and EC certificates while
    including RSA-2048.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html
    """
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-keyfilter-").rstrip("-").lower() + ".example.com"

    rsa2048_pem, rsa2048_key = _mint("rsa2048." + base, key="rsa2048")
    rsa2048_arn = _import(ctx, acm, rsa2048_pem, rsa2048_key)
    rsa4096_pem, rsa4096_key = _mint("rsa4096." + base, key="rsa4096")
    rsa4096_arn = _import(ctx, acm, rsa4096_pem, rsa4096_key)
    ec_pem, ec_key = _mint("ec256." + base, key="ec256")
    ec_arn = _import(ctx, acm, ec_pem, ec_key)

    mine = {rsa2048_arn: "RSA_2048", rsa4096_arn: "RSA_4096", ec_arn: "EC_prime256v1"}
    assert len(mine) == 3, f"the three imports collapsed into {len(mine)} ARN(s)"

    # Precondition: all three are indexed. Uses the widest possible filter so this
    # wait cannot be satisfied or defeated by the default filter.
    all_types = _poll_until(
        lambda: _arns(acm, Includes={"keyTypes": list(_ALL_KEY_TYPES)}),
        lambda seen: set(mine) <= seen,
        timeout_s=180,
        interval_s=5,
        description="all three imported certificates indexed in ListCertificates",
    )
    assert set(mine) <= all_types, sorted(set(mine) - all_types)

    # Each certificate must also self-report the key type this check filters on,
    # otherwise a filter assertion below would be testing the wrong thing.
    for arn, expected in mine.items():
        desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        assert desc["KeyAlgorithm"] == expected.replace("_", "-"), (
            f"{arn} reports KeyAlgorithm={desc['KeyAlgorithm']!r}, expected "
            f"{expected.replace('_', '-')!r} -- the filter cases below assume this mapping"
        )

    # (1)-(3) A single-value filter must include exactly its own and exclude the rest.
    cases = (
        (["RSA_2048"], {rsa2048_arn}, {rsa4096_arn, ec_arn}),
        (["RSA_4096"], {rsa4096_arn}, {rsa2048_arn, ec_arn}),
        (["EC_prime256v1"], {ec_arn}, {rsa2048_arn, rsa4096_arn}),
        (["RSA_2048", "RSA_4096"], {rsa2048_arn, rsa4096_arn}, {ec_arn}),
    )
    for key_types, must_include, must_exclude in cases:
        got = _arns(acm, Includes={"keyTypes": key_types})
        missing = must_include - got
        assert not missing, (
            f"Includes.keyTypes={key_types} omitted certificates of exactly those "
            f"types: {sorted(missing)}"
        )
        extra = must_exclude & got
        assert not extra, (
            f"Includes.keyTypes={key_types} returned certificates of other key types "
            f"({sorted((a, mine[a]) for a in extra)}): the filter is being ignored"
        )

    # (4) `Includes.extendedKeyUsage` is a second, INDEPENDENT filter on the same rows,
    #     and it partitions this check's certificates cleanly in BOTH directions: the
    #     three above carry no extendedKeyUsage extension (real ACM reports the `NONE`
    #     sentinel for them) while `eku_arn` carries TLS web server authentication.
    #     Two-sided on each side, so an emulator that ignores the member -- or that
    #     answers every extendedKeyUsage filter with an empty page, which would make a
    #     one-sided absence assertion vacuous -- fails.
    eku_pem, eku_key = _mint("eku." + base, key="rsa2048", server_auth_eku=True)
    eku_arn = _import(ctx, acm, eku_pem, eku_key)
    eku_desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=eku_arn)["Certificate"],
        lambda d: d.get("ExtendedKeyUsages") is not None,
        timeout_s=120,
        interval_s=3,
        description="the EKU certificate's parsed extendedKeyUsage published",
    )
    assert eku_desc["ExtendedKeyUsages"] == [
        {"Name": "TLS_WEB_SERVER_AUTHENTICATION", "OID": "1.3.6.1.5.5.7.3.1"}
    ], (
        "the EKU certificate's extension must be parsed out of the DER before the "
        f"filter below can mean anything; got {eku_desc.get('ExtendedKeyUsages')!r}"
    )
    none_eku = _poll_until(
        lambda: _arns(
            acm, Includes={"keyTypes": list(_ALL_KEY_TYPES), "extendedKeyUsage": ["NONE"]}
        ),
        lambda seen: set(mine) <= seen,
        timeout_s=180,
        interval_s=5,
        description="the three EKU-less certificates indexed under extendedKeyUsage=[NONE]",
    )
    assert set(mine) <= none_eku, (
        "certificates with no extendedKeyUsage extension must appear under "
        f"Includes.extendedKeyUsage=[NONE]: missing {sorted(set(mine) - none_eku)}"
    )
    assert eku_arn not in none_eku, (
        "a certificate that DOES carry TLS_WEB_SERVER_AUTHENTICATION must not appear "
        f"under Includes.extendedKeyUsage=[NONE]: {eku_arn}"
    )
    server_eku = _poll_until(
        lambda: _arns(
            acm,
            Includes={
                "keyTypes": list(_ALL_KEY_TYPES),
                "extendedKeyUsage": ["TLS_WEB_SERVER_AUTHENTICATION"],
            },
        ),
        lambda seen: eku_arn in seen,
        timeout_s=180,
        interval_s=5,
        description="the EKU certificate indexed under extendedKeyUsage=[TLS_WEB_SERVER_AUTHENTICATION]",
    )
    assert eku_arn in server_eku, (
        "the certificate carrying TLS_WEB_SERVER_AUTHENTICATION must appear under "
        f"Includes.extendedKeyUsage=[TLS_WEB_SERVER_AUTHENTICATION]: {eku_arn}"
    )
    leaked = set(mine) & server_eku
    assert not leaked, (
        "certificates with NO extendedKeyUsage extension must never appear under "
        f"Includes.extendedKeyUsage=[TLS_WEB_SERVER_AUTHENTICATION]: {sorted(leaked)}"
    )

    # (5) The DEFAULT filter is not "everything": it excludes RSA-4096 and EC keys.
    default = _arns(acm)
    assert rsa2048_arn in default, (
        "an RSA-2048 certificate must appear in an unfiltered ListCertificates "
        f"(default filtering includes RSA_2048); {rsa2048_arn} did not"
    )
    assert rsa4096_arn not in default, (
        "ListCertificates applies a default keyTypes filter that excludes RSA_4096, "
        f"but {rsa4096_arn} was returned with no Includes"
    )
    assert ec_arn not in default, (
        "ListCertificates applies a default keyTypes filter that excludes EC, "
        f"but {ec_arn} was returned with no Includes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
