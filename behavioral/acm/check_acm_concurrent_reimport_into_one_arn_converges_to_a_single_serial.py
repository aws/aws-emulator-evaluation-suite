"""acm-concurrent-reimport-into-one-arn-converges-to-a-single-serial."""
from __future__ import annotations

import concurrent.futures
import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-concurrent-reimport-into-one-arn-converges-to-a-single-serial"
GROUP = 'concurrency'
SERVICES = ['acm']

_ALL_KEY_TYPES = [
    "RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
    "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
]
_RACERS = 6

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


def _serial_int(text):
    """ACM's colon-grouped hex `Serial` as an integer.

    Compared as an INTEGER on purpose. ACM renders the serial as zero-padded hex BYTES, so a
    serial whose leading byte is below 0x10 comes back as `0a:...` while Python's `f"{n:x}"`
    produces `a...` -- a one-in-sixteen string mismatch that has nothing to do with fidelity.
    """
    return int(str(text).replace(":", ""), 16)


def _crypto():
    """Lazily import `cryptography`; an absent module raises ImportError."""
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


def _arns_for_domain(acm, domain):
    """Every certificate ARN in the account carrying `domain`, fully paginated.

    The default ListCertificates keyTypes filter is narrower than the enum, so the widened filter
    and full pagination are both needed.
    """
    out = []
    for page in acm.get_paginator("list_certificates").paginate(
            Includes={"keyTypes": list(_ALL_KEY_TYPES)}):
        for summary in page["CertificateSummaryList"]:
            if summary.get("DomainName") == domain:
                out.append(summary["CertificateArn"])
    return sorted(out)


@tags("axis:happy-path", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Six concurrent re-imports into one ARN: at least one succeeds, every loser gets
    ConflictException, and the certificate converges on one racer's serial and PEM, same ARN.

    Reference: https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html
    """
    acm = ctx.client("acm")
    uid = ctx.unique_name("sim2real-behav-race-")
    host = f"{uid}.example.com"

    root, root_key = _root_ca(f"root-{uid}")
    base_leaf, base_key = _leaf(host, [host], f"root-{uid}", root_key)
    resp = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(base_leaf), PrivateKey=_key_pem(base_key), CertificateChain=_pem(root),
        Tags=[{"Key": "sim2real", "Value": CHECK}]))
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0))
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=120, interval_s=3,
        description="the base certificate reaches ISSUED before the race",
    )
    # Every re-import targets this one ARN, so the ONLY certificate this check can leak is the one
    # already registered for cleanup above. Establish the pre-race inventory behind a membership
    # poll, because ListCertificates lags DescribeCertificate.
    arns_before = _poll_until(
        lambda: _arns_for_domain(acm, host),
        lambda arns: arn in arns,
        timeout_s=180, interval_s=5,
        description="the base certificate is indexed in ListCertificates",
    )
    assert arns_before == [arn], (
        f"the pre-race inventory for {host!r} must be exactly the base certificate; got "
        f"{arns_before!r}"
    )

    racers = [_leaf(host, [host], f"root-{uid}", root_key) for _ in range(_RACERS)]
    serials = {cert.serial_number: idx for idx, (cert, _k) in enumerate(racers)}
    assert len(serials) == _RACERS, (
        f"the {_RACERS} racing certificates must have distinct serials; got "
        f"{sorted(f'{n:x}' for n in serials)!r}"
    )
    pems = {cert.serial_number: _pem(cert) for cert, _k in racers}

    def _reimport(idx):
        cert, key = racers[idx]
        try:
            acm.import_certificate(
                CertificateArn=arn, Certificate=_pem(cert), PrivateKey=_key_pem(key),
                CertificateChain=_pem(root))
        except ClientError as exc:
            messages[idx] = exc.response.get("Error", {}).get("Message")
            return idx, exc.response.get("Error", {}).get("Code")
        return idx, None

    messages = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=_RACERS) as pool:
        outcomes = dict(pool.map(_reimport, range(_RACERS)))

    succeeded = sorted(i for i, code in outcomes.items() if code is None)
    failed = {i: code for i, code in outcomes.items() if code is not None}
    # (1) The race must not be a total loss -- if nothing was accepted there is no convergence to
    #     assert and the check would be vacuous.
    assert succeeded, (
        f"at least one of the {_RACERS} concurrent re-imports must be accepted; every one failed: "
        f"{failed!r}"
    )
    # (2) Every refusal is the ONE code ACM uses to serialise this race. Asserted per
    #     thread rather than as a set membership, so it is a single exact code each time and an
    #     emulator that raises anything else -- or that raises nothing and silently interleaves
    #     writes -- fails here. How MANY threads lose the race is scheduling, so it is not
    #     asserted; that a loser is told it lost, with this code, is the contract.
    for idx, code in sorted(failed.items()):
        assert code == "ConflictException", (
            f"a concurrent re-import that loses the race must be refused with "
            f"'ConflictException'; thread {idx} got {code!r}. Full partition: succeeded="
            f"{succeeded!r}, failed={failed!r}"
        )
        assert messages[idx] == f"Import of certificate with {arn} already in progress.", messages[idx]

    # (3) Convergence: the serial stops moving, and the value it stops on is one of ours.
    def _serial():
        raw = acm.describe_certificate(CertificateArn=arn)["Certificate"].get("Serial")
        return _serial_int(raw) if raw else None

    # Two consecutive identical reads, since DescribeCertificate is eventually consistent.
    stable = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        first = _serial()
        time.sleep(4)
        if first is not None and first == _serial():
            stable = first
            break
    assert stable is not None, (
        f"the certificate's Serial never settled within 180s after the race; last read "
        f"{_serial()!r}"
    )
    assert stable in serials, (
        f"the converged Serial {stable:x} is not one of the {_RACERS} certificates that were "
        f"imported: {sorted(f'{n:x}' for n in serials)!r} (the pre-race base serial was "
        f"{base_leaf.serial_number:x})"
    )

    # (4) The ARN is stable: re-import replaces content, it never mints a new identity.
    final = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert final["CertificateArn"] == arn, (
        f"the ARN changed under concurrent re-import: {final['CertificateArn']!r} vs {arn!r}"
    )
    assert final["Status"] == "ISSUED", (
        f"the certificate must still be ISSUED after the race; got {final['Status']!r}"
    )
    assert final["Type"] == "IMPORTED", f"Type became {final['Type']!r}"

    # (5) Metadata and content agree: the PEM served is the winner's PEM, not another racer's.
    served = _retry_throttle(lambda: acm.get_certificate(CertificateArn=arn))["Certificate"]
    winner_pem = pems[stable].decode()
    assert served.strip() == winner_pem.strip(), (
        f"DescribeCertificate reports serial {stable!r} but GetCertificate returns a different "
        f"certificate; served {served[:60]!r}... expected {winner_pem[:60]!r}..."
    )

    # (6) No extra resource: the race did not fan out into seven certificates.
    arns_after = _arns_for_domain(acm, host)
    assert arns_after == [arn], (
        f"the race must leave exactly the one certificate for {host!r}; the paginated list holds "
        f"{arns_after!r} (before the race it held {arns_before!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
