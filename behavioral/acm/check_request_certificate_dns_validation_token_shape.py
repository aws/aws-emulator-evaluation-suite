"""request-certificate-dns-validation-token-shape."""
from __future__ import annotations

import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-certificate-dns-validation-token-shape"
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


_CNAME_NAME_RE = re.compile(r"^_[0-9a-f]{32}\.(?P<domain>[^.]+(?:\.[^.]+)+)\.$")
_CNAME_VALUE_RE = re.compile(r"^_[0-9a-f]{32}\.[a-z0-9]+\.acm-validations(?:\.[a-z0-9-]+)+\.$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DNS-validated request mints one CNAME challenge per distinct name, shaped
    `_<32 hex>.<name>.` -> `_<32 hex>.<label>.acm-validations.<domain>.`, stable across reads.

    Reference: https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html
    """
    acm = ctx.client("acm")
    apex = _unique_domain(ctx, "dnstok")
    parent = apex.split(".", 1)[1]
    alt_one = "one." + parent
    alt_two = "two." + parent

    arn = _request(
        ctx,
        acm,
        DomainName=apex,
        SubjectAlternativeNames=[apex, alt_one, alt_two],
        ValidationMethod="DNS",
        IdempotencyToken=uuid.uuid4().hex[:24],
    )

    def _opts():
        desc = acm.describe_certificate(CertificateArn=arn)["Certificate"]
        return desc

    desc = _poll_until(
        _opts,
        lambda d: len(d.get("DomainValidationOptions") or []) == 3
        and all("ResourceRecord" in o for o in d["DomainValidationOptions"]),
        timeout_s=180,
        interval_s=5,
        description="all three DNS validation challenge records published",
    )

    assert desc["Status"] == "PENDING_VALIDATION", desc["Status"]
    assert desc["Type"] == "AMAZON_ISSUED", desc["Type"]
    assert desc["DomainName"] == apex, desc["DomainName"]
    assert set(desc["SubjectAlternativeNames"]) == {apex, alt_one, alt_two}, (
        f"SubjectAlternativeNames={sorted(desc['SubjectAlternativeNames'])}"
    )
    assert desc["InUseBy"] == [], desc["InUseBy"]
    for absent in ("Serial", "NotBefore", "NotAfter"):
        assert absent not in desc, (
            f"nothing has been signed yet, so {absent} must be absent while "
            f"PENDING_VALIDATION; got {desc.get(absent)!r}"
        )
    assert "CertificateAuthorityArn" not in desc, (
        "a public request has no private CA; got "
        f"{desc.get('CertificateAuthorityArn')!r}"
    )

    # The apex is listed as both DomainName and a SAN; options are de-duplicated per name.
    opts = desc["DomainValidationOptions"]
    assert len(opts) == 3, (
        f"the apex was supplied as both DomainName and a SAN, so there must be 3 "
        f"de-duplicated validation options, got {len(opts)}"
    )
    by_name = {o["DomainName"]: o for o in opts}
    assert set(by_name) == {apex, alt_one, alt_two}, (
        f"validation options cover {sorted(by_name)}, expected "
        f"{sorted({apex, alt_one, alt_two})}"
    )

    tokens = set()
    values = set()
    for name, opt in sorted(by_name.items()):
        assert opt["ValidationMethod"] == "DNS", f"{name}: {opt.get('ValidationMethod')!r}"
        assert opt["ValidationStatus"] == "PENDING_VALIDATION", (
            f"{name}: {opt.get('ValidationStatus')!r}"
        )
        assert opt["ValidationDomain"] == name, (
            f"{name}: ValidationDomain={opt.get('ValidationDomain')!r}"
        )
        rr = opt["ResourceRecord"]
        assert rr["Type"] == "CNAME", f"{name}: ResourceRecord.Type={rr['Type']!r}"

        m = _CNAME_NAME_RE.match(rr["Name"])
        assert m, (
            f"{name}: ResourceRecord.Name={rr['Name']!r} is not of the form "
            "_<32 hex>.<domain>. -- a DNS-validation workflow cannot use it"
        )
        assert m.group("domain") == name, (
            f"{name}: the challenge CNAME is scoped to {m.group('domain')!r}, so "
            "publishing it would validate a different name"
        )
        assert rr["Name"].endswith("."), (
            f"{name}: ResourceRecord.Name must be fully qualified with a trailing "
            f"dot, got {rr['Name']!r}"
        )

        assert _CNAME_VALUE_RE.match(rr["Value"]), (
            f"{name}: ResourceRecord.Value={rr['Value']!r} is not of the form "
            "_<32 hex>.<label>.acm-validations.<domain>."
        )
        tokens.add(rr["Name"].split(".", 1)[0])
        values.add(rr["Value"])

    assert len(tokens) == 3, (
        f"each name must get its own challenge token; got {len(tokens)} distinct "
        f"token(s) across 3 names: {sorted(tokens)}"
    )
    assert len(values) == 3, (
        f"each name must get its own CNAME target; got {len(values)} distinct "
        f"value(s) across 3 names"
    )

    # Re-minting a token on every Describe would break any publish-then-wait workflow.
    again = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    again_by_name = {
        o["DomainName"]: o["ResourceRecord"] for o in again["DomainValidationOptions"]
    }
    for name, opt in by_name.items():
        assert again_by_name[name]["Name"] == opt["ResourceRecord"]["Name"], (
            f"{name}: the challenge record name changed between two DescribeCertificate "
            f"calls ({opt['ResourceRecord']['Name']!r} -> {again_by_name[name]['Name']!r})"
        )
        assert again_by_name[name]["Value"] == opt["ResourceRecord"]["Value"], (
            f"{name}: the challenge record value changed between two DescribeCertificate calls"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
