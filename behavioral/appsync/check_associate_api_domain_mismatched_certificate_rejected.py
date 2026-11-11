"""associate-api-domain-mismatched-certificate-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-api-domain-mismatched-certificate-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """CreateDomainName rejects a certificate/domain pair whose SAN does not cover the domain --
    BadRequestException, with no DomainName resource created, so AssociateApi can never reach it.
    Positive control: the same certificate registers cleanly against the domain it covers.
    """
    appsync = ctx.client("appsync")

    zone_id, apex = _dns_zone(ctx)
    covered_domain = f"{_domain_label()}.{apex}"
    mismatched_domain = f"{_domain_label()}.{apex}"
    cert_arn = _dns_validated_cert(ctx, zone_id, covered_domain)

    # Positive control: the real, DNS-validated certificate registers cleanly against the
    # domain it actually covers. Proves the account/credentials/validation path is healthy
    # before the negative below, and absorbs the real (but bounded) ACM->AppSync propagation
    # lag right after issuance.
    _create_domain_name_with_retry(appsync, covered_domain, cert_arn)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_domain_name(domainName=covered_domain)))
    got = appsync.get_domain_name(domainName=covered_domain)["domainNameConfig"]
    assert got["domainName"] == covered_domain
    assert got["certificateArn"] == cert_arn

    # Negative: the SAME certificate against a domain it does not cover at all. Unlike the
    # propagation lag the positive control above absorbs, a genuine content mismatch never
    # clears -- one attempt is enough; TooManyRequestsException (an unrelated account-level
    # throttle) is the only thing worth retrying past.
    # Registered before the attempt, so a target that wrongly creates the domain still deletes it
    # (before the certificate) rather than leaving the certificate in use.
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appsync.delete_domain_name(domainName=mismatched_domain))
    )
    code = _create_domain_name_expect_rejection(appsync, mismatched_domain, cert_arn)
    assert code == "BadRequestException", (
        f"expected BadRequestException registering a domain the certificate does not cover, got {code!r}"
    )

    not_found = _error(lambda: appsync.get_domain_name(domainName=mismatched_domain))
    assert not_found == ("NotFoundException", "Domain name not found"), (
        "CreateDomainName must not create a DomainName resource for a certificate/domain "
        f"mismatch, but GetDomainName returned {not_found!r}"
    )


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_domain_name_with_retry(appsync, domain: str, cert_arn: str, *, timeout_s: float = 60.0):
    """Even after ACM reports the certificate ISSUED, AppSync's own certificate validation
    (which resolves the cert through ACM in us-east-1) can trail that state by tens of seconds,
    surfacing as BadRequestException("Certificate is invalid") on the first attempt or two."""
    deadline = time.monotonic() + timeout_s
    delay = 5.0
    while True:
        try:
            return appsync.create_domain_name(domainName=domain, certificateArn=cert_arn)
        except ClientError as exc:
            err = exc.response["Error"]
            code = err.get("Code")
            message = err.get("Message", "").lower()
            transient = code == "TooManyRequestsException" or (
                code == "BadRequestException" and "certificate is invalid" in message
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 20.0)


def _create_domain_name_expect_rejection(appsync, domain: str, cert_arn: str, *, timeout_s: float = 30.0):
    """Retry only past the account-level TooManyRequestsException throttle; a BadRequestException
    (the expected outcome for a certificate that does not cover this domain) is returned
    immediately rather than absorbed."""
    deadline = time.monotonic() + timeout_s
    delay = 5.0
    while True:
        try:
            appsync.create_domain_name(domainName=domain, certificateArn=cert_arn)
            return None
        except ClientError as exc:
            code = exc.response["Error"].get("Code")
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                return code
            time.sleep(delay)
            delay = min(delay * 2, 20.0)


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _dns_zone(ctx):
    """(zone id, apex) of the DNS baseline zone the check writes validation records into
    (``requires:dns-baseline``, docs/TAXONOMY.md)."""
    route53 = ctx.client("route53")
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            if zone["Config"].get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            tags = route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=zone_id)
            if _BASELINE_TAG in tags["ResourceTagSet"]["Tags"]:
                return zone_id, zone["Name"].rstrip(".")
    raise AssertionError(
        "this account has no DNS baseline zone: a public hosted zone, delegated from its "
        "parent, tagged for the DNS validation this check needs (requires:dns-baseline)"
    )


def _domain_label() -> str:
    """A label short enough that label.apex fits ACM's 64-octet first domain name."""
    return f"sim2real{uuid.uuid4().hex[:8]}"


def _dns_validated_cert(ctx, zone_id: str, domain: str) -> str:
    """An ACM certificate for ``domain`` in us-east-1, issued by DNS validation through
    ``zone_id``: AppSync's CreateDomainName accepts only a certificate ACM itself issued, from
    us-east-1 (custom domains are CloudFront-backed)."""
    acm = ctx.client("acm", region="us-east-1")
    route53 = ctx.client("route53")
    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        IdempotencyToken=uuid.uuid4().hex[:24],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, arn))

    def _record():
        options = acm.describe_certificate(CertificateArn=arn)["Certificate"].get(
            "DomainValidationOptions", []
        )
        return options[0].get("ResourceRecord") if options else None

    record = _wait_for(_record, lambda r: r is not None, 120, f"validation record of {domain}")
    record_set = {
        "Name": record["Name"],
        "Type": record["Type"],
        "TTL": 60,
        "ResourceRecords": [{"Value": record["Value"]}],
    }
    route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": "UPSERT", "ResourceRecordSet": record_set}]},
    )
    ctx.on_cleanup(
        lambda: route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": record_set}]},
        )
    )
    _wait_for(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"],
        lambda s: s in ("ISSUED", "FAILED", "VALIDATION_TIMED_OUT"),
        600,
        f"certificate for {domain} to leave PENDING_VALIDATION",
    )
    status = acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"]
    assert status == "ISSUED", f"DNS-validated certificate for {domain} ended {status!r}"
    return arn


def _wait_for(probe, predicate, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(5)
    raise AssertionError(f"{what} not met within {timeout_s}s (last={last!r})")


def _delete_certificate(acm, arn: str, timeout_s: float = 180.0) -> None:
    """AppSync releases a deleted domain's certificate a little after DeleteDomainName returns."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
