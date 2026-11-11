"""dns-validation-cname-collapses-wildcard-onto-its-apex-and-is-unique-per-san."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dns-validation-cname-collapses-wildcard-onto-its-apex-and-is-unique-per-san"
GROUP = "server-side"
SERVICES = ["acm"]

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


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on deadline (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _random_apex():
    """A parent label no account owns, under a real TLD.

    A reserved name (`example.com`) is asynchronously failed by ACM with
    ADDITIONAL_VERIFICATION_REQUIRED, which would leave no PENDING_VALIDATION options to read.
    """
    return f"sim2realprobe{uuid.uuid4().hex[:12]}.com"


def _leading_token(label):
    """The single leading `_<token>` label of a validation record, or a loud failure."""
    head = label.rstrip(".").split(".", 1)[0]
    assert head.startswith("_") and len(head) > 1, (
        f"an ACM validation label must be an underscore followed by a token; got {head!r}"
    )
    return head


def _domain_validation_options(acm, arn):
    """DescribeCertificate's per-name validation options, keyed by requested DomainName.

    Hard-subscripted: a missing key fails loudly rather than defaulting to empty.
    """
    detail = _retry_throttle(lambda: acm.describe_certificate(CertificateArn=arn))["Certificate"]
    options = detail["DomainValidationOptions"]
    return detail, {opt["DomainName"]: opt for opt in options}


def _all_options_have_records(pair, expected_names):
    _detail, by_name = pair
    return set(by_name) == expected_names and all(
        "ResourceRecord" in opt for opt in by_name.values()
    )


def _list_validation_domains(acm, arn):
    """Every DomainName reported by ListCertificateDomainValidations, following NextToken."""
    names, token = set(), None
    while True:
        kwargs = {"CertificateArn": arn}
        if token:
            kwargs["NextToken"] = token
        page = _retry_throttle(
            lambda kw=dict(kwargs): acm.list_certificate_domain_validations(**kw))
        for summary in page["DomainValidationSummaryList"]:
            names.add(summary["DomainName"])
        token = page.get("NextToken")
        if not token:
            return names


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ACM strips `*.` when minting DNS validation records: a wildcard and its apex get the same
    CNAME, owned by the apex, while every other name gets its own; each CNAME's name and value
    carry different tokens.

    Reference: https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html
    """
    acm = ctx.client("acm")

    apex = _random_apex()
    wildcard = f"*.{apex}"
    www = f"www.{apex}"
    deep = f"host.sub.{apex}"
    requested = [apex, wildcard, www, deep]
    expected_names = set(requested)

    arn = _retry_throttle(lambda: acm.request_certificate(
        DomainName=apex,
        ValidationMethod="DNS",
        SubjectAlternativeNames=requested,
        IdempotencyToken=uuid.uuid4().hex[:24],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]
    ctx.on_cleanup(lambda: _retry_throttle(
        lambda: acm.delete_certificate(CertificateArn=arn), attempts=4, base_delay=3.0))

    detail, by_name = _poll_until(
        lambda: _domain_validation_options(acm, arn),
        lambda pair: _all_options_have_records(pair, expected_names),
        timeout_s=180, interval_s=5,
        description=(
            f"all four requested names publishing a DNS validation ResourceRecord "
            f"({sorted(expected_names)})"
        ),
    )

    # The request must not have been fast-failed: a FAILED certificate publishes no usable
    # challenge and would make every rule below vacuous.
    assert detail["Status"] == "PENDING_VALIDATION", (
        f"the certificate for {apex!r} must be awaiting DNS proof; Status is "
        f"{detail['Status']!r} (FailureReason {detail.get('FailureReason')!r})"
    )

    # (1) One validation option per requested name -- the wildcard included.
    assert set(by_name) == expected_names, (
        f"DescribeCertificate must publish one DomainValidationOptions entry per requested "
        f"name; expected {sorted(expected_names)}, got {sorted(by_name)}"
    )

    records = {}
    for name, opt in by_name.items():
        assert opt["ValidationMethod"] == "DNS", (
            f"{name!r} must be on the DNS challenge, got {opt['ValidationMethod']!r}"
        )
        record = opt["ResourceRecord"]
        assert record["Type"] == "CNAME", (
            f"the challenge for {name!r} must be a CNAME, got {record['Type']!r}"
        )
        records[name] = (record["Name"].rstrip("."), record["Value"].rstrip("."))

    # (2) THE documented collapse, and the reason this check exists: the wildcard and its apex
    #     share ONE record, name and value.
    assert records[wildcard] == records[apex], (
        f"ACM removes the wildcard label when minting a validation record, so {wildcard!r} and "
        f"{apex!r} must be handed an IDENTICAL CNAME; got {records[wildcard]!r} for the wildcard "
        f"and {records[apex]!r} for the apex"
    )

    # (3) The collapse is a STRIPPING, not an aliasing: the shared record's owner name is the
    #     apex, so it is a legal DNS name. `_token.*.apex` would not be.
    shared_name = records[apex][0]
    shared_parent = shared_name.split(".", 1)[1]
    assert shared_parent == apex, (
        f"the record shared by {wildcard!r} and {apex!r} must be owned by the apex with the "
        f"wildcard label REMOVED, so that it is a publishable DNS name; its owner is "
        f"{shared_name!r}, whose parent is {shared_parent!r} and not {apex!r}"
    )
    assert "*" not in shared_name, (
        f"a wildcard label can never appear in a DNS owner name; the challenge name is "
        f"{shared_name!r}"
    )

    # (4) Both sides of one CNAME use DIFFERENT tokens.
    for name, (record_name, record_value) in records.items():
        assert _leading_token(record_name) != _leading_token(record_value), (
            f"the CNAME for {name!r} uses the same token on both sides ({record_name!r} -> "
            f"{record_value!r}); ACM documents the value as carrying a different token"
        )

    # (5) Four names, exactly three distinct records -- and the two non-collapsing names are
    #     each their own.
    distinct = set(records.values())
    assert len(distinct) == 3, (
        f"four names of which exactly two collapse must yield 3 distinct CNAME records; got "
        f"{len(distinct)}: {sorted(distinct)}"
    )
    assert records[www] != records[apex] and records[www] != records[deep], (
        f"a subdomain must be validated by its own record; www={records[www]!r} "
        f"apex={records[apex]!r} deep={records[deep]!r}"
    )
    assert records[deep] != records[apex], (
        f"a two-label subdomain must not collapse onto the apex; deep={records[deep]!r} "
        f"apex={records[apex]!r}"
    )

    # (6) An independent read through a different operation agrees on exactly which names are
    #     under validation, wildcard included.
    listed = _list_validation_domains(acm, arn)
    assert listed == expected_names, (
        f"ListCertificateDomainValidations must index the same four names; got "
        f"{sorted(listed)}, expected {sorted(expected_names)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
