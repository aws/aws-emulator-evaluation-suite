"""request-certificate-dns-validation-resource-record."""
from __future__ import annotations

import re
import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-dns-validation-resource-record"
GROUP = 'lifecycle'
SERVICES = ['acm']

# Real DNS-validation CNAME shape: Name is the challenge token scoped to the exact validated name,
# Value is `_<32 hex>.<label>.acm-validations.<domain>.` in ACM's own validation zone, whose domain
# is the target's. Confirmed against real AWS.
_CNAME_NAME_RE = re.compile(r"^_[0-9a-f]{32}\.(?P<domain>[^.]+(?:\.[^.]+)+)\.$")
_CNAME_VALUE_RE = re.compile(r"^_[0-9a-f]{32}\.[a-z0-9]+\.acm-validations(?:\.[a-z0-9-]+)+\.$")

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

def _unique_domain(ctx, prefix="chk"):
    """Unique DNS name under a random, non-reserved parent so the request stays on the normal
    PENDING_VALIDATION path (reserved names like example.com are fast-failed by ACM risk assessment,
    which would suppress the DNS validation ResourceRecord this check asserts on)."""
    raw = ctx.unique_name(prefix)
    label = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw.lower())
    label = label.strip("-") or "chk"
    label = label[:50]
    parent = f"sim2realprobe{uuid.uuid4().hex[:10]}"
    return f"{label}.{parent}.com"

def _request_pending(ctx, acm, prefix="req", validation_method=None, **kwargs):
    """RequestCertificate under a random parent label so it stays PENDING_VALIDATION. Returns (arn, domain)."""
    domain = _unique_domain(ctx, prefix)
    params = {"DomainName": domain}
    if validation_method:
        params["ValidationMethod"] = validation_method
    params.update(kwargs)
    tag_key = ctx.unique_name("sim2real-acm-dv-")
    resp = _retry_throttle(
        lambda: acm.request_certificate(Tags=[{"Key": tag_key, "Value": "true"}], **params)
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _retry_throttle(
            lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0
        )
    )
    return arn, domain

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DNS-validated RequestCertificate exposes a CNAME ResourceRecord for domain proof.

    The ResourceRecord is populated asynchronously, so poll until it appears; the CNAME name is
    derived from and scoped to the requested domain.
    """
    acm = ctx.client("acm")
    arn, domain = _request_pending(ctx, acm, prefix="dns", validation_method="DNS")

    def _probe():
        return acm.describe_certificate(CertificateArn=arn)["Certificate"]

    def _has_record(desc):
        opts = desc.get("DomainValidationOptions", [])
        return bool(opts) and "ResourceRecord" in opts[0]

    desc = _poll_until(
        _probe, _has_record, timeout_s=90, interval_s=3,
        description="DNS validation ResourceRecord published",
    )
    opt = desc["DomainValidationOptions"][0]
    assert opt["ValidationMethod"] == "DNS", opt
    record = opt["ResourceRecord"]
    assert record["Type"] == "CNAME", record
    # The CNAME name is the DNS-validation challenge token, minted for and scoped to
    # exactly this domain: `_<32 hex>.<domain>.` -- not an echo, not a placeholder.
    name_match = _CNAME_NAME_RE.match(record["Name"])
    assert name_match, (
        f"ResourceRecord.Name={record['Name']!r} is not of the form "
        "_<32 hex>.<domain>. -- a DNS-validation workflow cannot use it"
    )
    assert name_match.group("domain") == domain, (
        f"challenge CNAME is scoped to {name_match.group('domain')!r}, expected {domain!r}"
    )
    # The CNAME value points into ACM's own validation zone, not an arbitrary string.
    assert _CNAME_VALUE_RE.match(record["Value"]), (
        f"ResourceRecord.Value={record['Value']!r} is not of the form "
        "_<32 hex>.<label>.acm-validations.<domain>."
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
