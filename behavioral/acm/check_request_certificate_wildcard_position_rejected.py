"""request-certificate-wildcard-position-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "request-certificate-wildcard-position-rejected"
GROUP = 'overly-permissive'
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


def _unique_domain(ctx, prefix="chk"):
    """Unique DNS name under a random, non-reserved parent so the request is accepted on the
    normal path (reserved names like example.com are fast-failed by ACM risk assessment)."""
    raw = ctx.unique_name(prefix)
    label = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw.lower())
    label = label.strip("-") or "chk"
    label = label[:50]
    parent = f"sim2realprobe{uuid.uuid4().hex[:10]}"
    return f"{label}.{parent}.com"


def _request(ctx, acm, **kwargs):
    """RequestCertificate + teardown registered at creation time. Returns the ARN."""
    arn = _retry_throttle(lambda: acm.request_certificate(**kwargs))["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn


_DOMAIN_PATTERN_MESSAGE = (
    "1 validation error detected: Value of the input at 'domainName' failed to satisfy "
    "constraint: Member must satisfy regular expression pattern: "
    r"(\*\.)?(((?!-)[A-Za-z0-9-]{0,62}[A-Za-z0-9])\.)+((?!-)[A-Za-z0-9-]{1,62}[A-Za-z0-9])"
)


def _error(ctx, acm, fn):
    """Call fn() and return the ClientError (code, message). A success raises, after registering
    the created certificate for cleanup: accepting a wildcard position AWS refuses is a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    arn = result.get("CertificateArn")
    if arn:
        ctx.on_cleanup(
            lambda: _retry_throttle(
                lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
            )
        )
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


# Every value of the modeled KeyAlgorithm enum. ListCertificates applies a DEFAULT
# keyTypes filter (the operation doc says RSA_2048 only; the Filters member doc says
# RSA_1024 + RSA_2048 -- the service model contradicts itself), so an
# effect-absent scan MUST pass keyTypes explicitly or it can miss a leaked certificate.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestCertificate accepts `*.d` as a PENDING_VALIDATION certificate validating the wildcard
    name, but refuses `*.*.d` and `a.*.d` with ValidationException and the exact pattern message,
    creating no certificate and leaving the control untouched."""
    acm = ctx.client("acm")
    apex = _unique_domain(ctx, "wildcard")
    parent = apex.split(".", 1)[1]
    good = "*." + parent
    double = "*.*." + parent
    inner = "a.*." + parent

    # --- control: a single leftmost wildcard is legal ---
    good_arn = _request(
        ctx,
        acm,
        DomainName=good,
        ValidationMethod="DNS",
        IdempotencyToken=uuid.uuid4().hex[:24],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    good_desc = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=good_arn)["Certificate"],
        lambda d: d.get("Status") is not None
        and len(d.get("DomainValidationOptions") or []) >= 1,
        timeout_s=180,
        interval_s=5,
        description="wildcard control certificate published",
    )
    assert good_desc["Status"] == "PENDING_VALIDATION", good_desc["Status"]
    assert good_desc["DomainName"] == good, (
        f"the wildcard must be preserved verbatim, got {good_desc['DomainName']!r}"
    )
    # A wildcard request validates the wildcard name itself, not the bare parent.
    good_opts = {o["DomainName"] for o in good_desc["DomainValidationOptions"]}
    assert good in good_opts, (
        f"the validation option must cover the wildcard name {good!r}, got {sorted(good_opts)}"
    )

    # ListCertificates indexing is eventually consistent, so the control must be listed before
    # the baseline is taken, or it would show up as a new certificate below.
    _poll_until(
        lambda: set(_list_summaries(acm)),
        lambda arns: good_arn in arns,
        timeout_s=180,
        interval_s=5,
        description="wildcard control certificate visible in ListCertificates",
    )
    before = set(_list_summaries(acm))

    # --- break exactly one thing, twice: wildcard position ---
    for bad, why in ((double, "two wildcard labels"), (inner, "a non-leftmost wildcard")):
        code, message = _error(
            ctx,
            acm,
            lambda bad=bad: acm.request_certificate(
                DomainName=bad,
                ValidationMethod="DNS",
                IdempotencyToken=uuid.uuid4().hex[:24],
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            ),
        )
        assert code == "ValidationException", (
            f"{bad!r} ({why}) is not a legal certificate name and must be refused with "
            f"ValidationException, got {code!r}"
        )
        assert message == _DOMAIN_PATTERN_MESSAGE, (
            f"{bad!r} ({why}): expected message {_DOMAIN_PATTERN_MESSAGE!r}, got {message!r}"
        )

    # --- the effect must be ABSENT: no new certificate, under any name ---
    after = _list_summaries(acm)
    new = set(after) - before
    assert not new, (
        f"the refused wildcard requests created {len(new)} certificate(s) anyway: "
        f"{[after[a].get('DomainName') for a in new]}"
    )
    stored = {s.get("DomainName") for s in after.values()}
    assert double not in stored, f"{double!r} was stored despite being refused"
    assert inner not in stored, f"{inner!r} was stored despite being refused"

    # --- the control must be untouched ---
    still = acm.describe_certificate(CertificateArn=good_arn)["Certificate"]
    assert still["Status"] == "PENDING_VALIDATION", still["Status"]
    assert still["DomainName"] == good, still["DomainName"]
    assert good_arn in after, "the control certificate disappeared"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
