"""domain-name-get-not-found-after-delete."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-get-not-found-after-delete"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """GetDomainName and UpdateDomainName on a deleted domain both return NotFoundException,
    not a stale record or a stale write."""
    appsync = ctx.client("appsync")
    # AppSync's CreateDomainName rejects the RFC 2606 reserved names (example.com and the like)
    # and any certificate ACM did not issue, so the domain lives under a zone that can
    # DNS-validate one.
    zone_id, apex = _dns_zone(ctx)
    domain_name = f"{_domain_label()}.{apex}"
    cert_arn = _dns_validated_cert(ctx, zone_id, domain_name)

    _create_domain_name_with_retry(appsync, domainName=domain_name, certificateArn=cert_arn)
    deleted = {"done": False}

    def _cleanup() -> None:
        if not deleted["done"]:
            appsync.delete_domain_name(domainName=domain_name)

    ctx.on_cleanup(_cleanup)

    # Positive control: the domain exists and GetDomainName succeeds while it is live.
    got = appsync.get_domain_name(domainName=domain_name)
    assert got["domainNameConfig"]["domainName"] == domain_name
    assert got["domainNameConfig"]["certificateArn"] == cert_arn

    appsync.delete_domain_name(domainName=domain_name)
    deleted["done"] = True

    code, message = _error_code(lambda: appsync.get_domain_name(domainName=domain_name))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code!r}"
    assert message == "Domain name not found", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )

    # A mutation on the now-dead id must also fail, not merely a read: UpdateDomainName is the
    # same lookup DeleteDomainName already resolved once.
    update_code, update_message = _error_code(
        lambda: appsync.update_domain_name(domainName=domain_name, description="post-delete")
    )
    assert update_code == "NotFoundException", (
        f"expected UpdateDomainName on the deleted domain to fail NotFoundException, got {update_code!r}"
    )
    assert update_message == "Domain name not found", (
        f"expected the exact NotFoundException message AWS returns for UpdateDomainName, got {update_message!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_domain_name_with_retry(appsync, timeout_s: float = 120.0, interval_s: float = 5.0, **kwargs):
    # Even after ACM reports the imported certificate as ISSUED, AppSync's own certificate
    # validation (which resolves the cert through ACM in us-east-1) can trail that state by tens of
    # seconds, surfacing as BadRequestException("Certificate is invalid") on the first one or two
    # attempts. Retry CreateDomainName across that propagation window; any other error is re-raised
    # immediately.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_domain_name(**kwargs)
        except Exception as exc:  # botocore.exceptions.ClientError
            error = getattr(exc, "response", {}).get("Error", {})
            if error.get("Code") == "BadRequestException" and "Certificate is invalid" in error.get("Message", ""):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


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
        f"this account has no DNS baseline zone (a public hosted zone tagged "
        f"{_BASELINE_TAG['Key']}={_BASELINE_TAG['Value']!r}, delegated from its parent)"
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
