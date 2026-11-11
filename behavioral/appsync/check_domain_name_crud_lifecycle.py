"""domain-name-crud-lifecycle."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-crud-lifecycle"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """CreateDomainName returns and GetDomainName reads back the domain, certificate and AppSync domain;
    UpdateDomainName's description persists on Get and in ListDomainNames; after DeleteDomainName,
    GetDomainName fails NotFoundException "Domain name not found"."""
    appsync = ctx.client("appsync")

    # CreateDomainName accepts only a certificate ACM issued, so the domain lives under a zone
    # that can DNS-validate one.
    zone_id, apex = _dns_zone(ctx)
    domain = f"{_domain_label()}.{apex}"
    cert_arn = _dns_validated_cert(ctx, zone_id, domain)

    created = _create_domain_name_with_retry(
        appsync,
        domainName=domain,
        certificateArn=cert_arn,
        description="initial description",
        tags={"Name": ctx.unique_name("sim2real-behav-appsync-domain-")},
    )["domainNameConfig"]

    def _cleanup_domain():
        try:
            appsync.delete_domain_name(domainName=domain)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_domain)

    assert created["domainName"] == domain
    assert created["certificateArn"] == cert_arn
    assert created["description"] == "initial description"
    assert created["appsyncDomainName"], "appsyncDomainName should be populated on create"
    # appsyncDomainName is the domain of the distribution AppSync creates for the custom domain: the CNAME
    # target, a host name of its own rather than the custom domain.
    appsync_domain = created["appsyncDomainName"]
    assert appsync_domain != domain and "." in appsync_domain.strip("."), (
        f"expected a separate host name as the CNAME target, got {appsync_domain!r}"
    )

    # GetDomainName reflects what was just created.
    fetched = appsync.get_domain_name(domainName=domain)["domainNameConfig"]
    assert fetched["domainName"] == domain
    assert fetched["certificateArn"] == cert_arn
    assert fetched["description"] == "initial description"
    assert fetched["appsyncDomainName"] == created["appsyncDomainName"]
    assert fetched["hostedZoneId"], "hostedZoneId should be populated"

    # UpdateDomainName changes description.
    updated = appsync.update_domain_name(domainName=domain, description="updated description")[
        "domainNameConfig"
    ]
    assert updated["description"] == "updated description"

    # The update persists across a fresh Get call.
    fetched_after_update = appsync.get_domain_name(domainName=domain)["domainNameConfig"]
    assert fetched_after_update["description"] == "updated description"
    assert fetched_after_update["domainName"] == domain

    # ListDomainNames contains it with the updated description.
    found = None
    paginator = appsync.get_paginator("list_domain_names")
    for page in paginator.paginate():
        for cfg in page.get("domainNameConfigs", []):
            if cfg["domainName"] == domain:
                found = cfg
                break
        if found:
            break
    assert found is not None, "domain not present in ListDomainNames"
    assert found["description"] == "updated description"

    # DeleteDomainName removes it; subsequent Get raises NotFoundException.
    appsync.delete_domain_name(domainName=domain)

    try:
        result = appsync.get_domain_name(domainName=domain)
    except ClientError as exc:
        error = exc.response["Error"]
    else:
        raise AssertionError(f"expected NotFoundException after DeleteDomainName, got {result!r}")
    assert error["Code"] == "NotFoundException", f"expected NotFoundException, got {error['Code']!r}"
    assert error.get("Message") == "Domain name not found", (
        f"expected the exact NotFoundException message, got {error.get('Message')!r}"
    )


# ===== helpers =====
def _create_domain_name_with_retry(appsync, *, timeout_s: float = 120, interval_s: float = 5, **kwargs):
    """CreateDomainName, retried while AppSync's certificate check trails ACM's ISSUED state
    ("Certificate is invalid") or the call is throttled, within a window well inside the check budget."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appsync.create_domain_name(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            code = err.get("Code")
            transient = (
                code == "TooManyRequestsException"
                or (code == "BadRequestException" and "certificate" in err.get("Message", "").lower())
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _dns_zone(ctx):
    """(zone id, apex) of the DNS baseline zone the check writes validation records into
    (``requires:dns-baseline``)."""
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
        "no DNS baseline zone found: a public hosted zone delegated from its parent "
        f"and tagged {_BASELINE_TAG['Key']}={_BASELINE_TAG['Value']}"
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
