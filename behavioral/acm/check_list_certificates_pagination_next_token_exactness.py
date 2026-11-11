"""list-certificates-pagination-next-token-exactness."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-certificates-pagination-next-token-exactness"
GROUP = 'lifecycle'
SERVICES = ['acm']

# The NextToken walk is deliberately NOT the boto3 paginator: the paginator hides the token,
# which is the thing under test.

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)

_MAX_PAGES = 150  # loop bound: a non-terminating NextToken must fail, not hang


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
    """Lazily import `cryptography`; raises (never skips) if it is absent."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _mint(common_name):
    """Mint a throwaway self-signed RSA-2048 pair. Returns (cert_pem, key_pem).

    The key is generated in-process and discarded with it; it is NOT a credential.
    """
    x509, hashes, serialization, rsa, NameOID = _crypto()
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        .sign(pkey, hashes.SHA256())
    )
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
    tags = kwargs.pop("Tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = _retry_throttle(
        lambda: acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem, Tags=tags, **kwargs)
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn


def _walk(acm, *, max_items, **kwargs):
    """Walk ListCertificates by hand, returning the list of (arns, next_token) pages."""
    pages = []
    token = None
    for _ in range(_MAX_PAGES):
        params = dict(kwargs)
        params["MaxItems"] = max_items
        if token is not None:
            params["NextToken"] = token
        resp = _retry_throttle(lambda p=params: acm.list_certificates(**p))
        arns = [c["CertificateArn"] for c in resp["CertificateSummaryList"]]
        token = resp.get("NextToken")
        pages.append((arns, token))
        if token is None:
            return pages
    raise AssertionError(
        f"ListCertificates never stopped returning NextToken after {_MAX_PAGES} pages of "
        f"MaxItems={max_items} -- pagination does not terminate (or the account holds "
        f"more than {_MAX_PAGES * max_items} certificates, which a test account should not)"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MaxItems=1 ListCertificates walk returns each certificate exactly once over disjoint pages
    with distinct tokens and terminates; MaxItems=100 covers the same set; a bad token is refused.

    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html"""
    acm = ctx.client("acm")
    base = ctx.unique_name("sim2real-behav-page-").rstrip("-").lower() + ".example.com"

    mine = []
    for i in range(3):
        cert_pem, key_pem = _mint(f"p{i}.{base}")
        mine.append(_import(ctx, acm, cert_pem, key_pem))
    mine_set = set(mine)
    assert len(mine_set) == 3, f"the three imports collapsed into {len(mine_set)} ARN(s): {mine}"

    # Wait until all three are visible in the default listing before paginating,
    # so a mid-walk appearance cannot be mistaken for a cursor defect.
    _poll_until(
        lambda: {
            c["CertificateArn"]
            for p in acm.get_paginator("list_certificates").paginate()
            for c in p["CertificateSummaryList"]
        },
        lambda seen: mine_set <= seen,
        timeout_s=180,
        interval_s=5,
        description="all three imported certificates indexed in ListCertificates",
    )

    pages = _walk(acm, max_items=1)

    # (1) MaxItems is a hard cap on every page.
    for i, (arns, _token) in enumerate(pages):
        assert len(arns) <= 1, (
            f"page {i} returned {len(arns)} certificates for MaxItems=1: the limit is "
            "not being applied"
        )

    # (2) NextToken presence is exactly "more pages follow".
    for i, (_arns, token) in enumerate(pages[:-1]):
        assert token, (
            f"page {i} of {len(pages)} omitted NextToken but the walk continued"
        )
    assert pages[-1][1] is None, (
        f"the final page still carried NextToken={pages[-1][1]!r}"
    )

    # (3) Distinct cursors -- a constant token is the classic infinite-loop bug.
    tokens = [t for _a, t in pages if t is not None]
    assert len(set(tokens)) == len(tokens), (
        f"ListCertificates reused a NextToken value across pages ({len(tokens)} tokens, "
        f"{len(set(tokens))} distinct): a client would loop forever"
    )

    # (4) Pages are strictly disjoint -- no certificate appears twice.
    flat = [a for arns, _t in pages for a in arns]
    assert len(flat) == len(set(flat)), (
        "the paginated walk returned duplicates: "
        f"{len(flat)} rows, {len(set(flat))} distinct ARNs"
    )

    # (5) The walk is complete: everything this check created is in it exactly once.
    for arn in mine:
        assert flat.count(arn) == 1, (
            f"{arn} appeared {flat.count(arn)} times in a MaxItems=1 walk, expected exactly 1"
        )

    # (6) A larger page size must cover the same set -- not a different one.
    big = _walk(acm, max_items=100)
    big_flat = [a for arns, _t in big for a in arns]
    assert len(big_flat) == len(set(big_flat)), "the MaxItems=100 walk returned duplicates"
    assert mine_set <= set(big_flat), (
        "the MaxItems=100 walk is missing certificates the MaxItems=1 walk returned: "
        f"{sorted(mine_set - set(big_flat))}"
    )
    for arns, _t in big:
        assert len(arns) <= 100, f"a page returned {len(arns)} rows for MaxItems=100"

    # (7) A malformed cursor must be refused, never silently restarted; ACM refuses it with
    # InvalidArgsException, not ValidationException.
    bad_token = "sim2real-not-a-valid-next-token"
    try:
        resp = acm.list_certificates(MaxItems=1, NextToken=bad_token)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "InvalidArgsException", (
            f"a malformed NextToken must be refused with InvalidArgsException "
            f"(confirmed against real AWS), got {code!r}"
        )
        expected_message = f"Invalid Next Token received {bad_token}"
        assert message == expected_message, (
            f"expected message {expected_message!r} (confirmed against real AWS), "
            f"got {message!r}"
        )
    else:
        raise AssertionError(
            "a malformed NextToken was accepted and silently restarted the walk, "
            f"returning {len(resp['CertificateSummaryList'])} row(s) with "
            f"NextToken={resp.get('NextToken')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
