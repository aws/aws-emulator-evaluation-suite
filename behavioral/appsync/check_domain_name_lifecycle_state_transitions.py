"""domain-name-lifecycle-state-transitions."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-name-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["appsync"]

# CreateDomainName accepts only an ACM-issued certificate, so the domain lives under the DNS
# baseline zone (requires:dns-baseline).
@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """CreateDomainName->GetDomainName(active)->UpdateDomainName(persists)->DeleteDomainName->GetDomainName not-found."""
    # AppSync custom domains require the ACM certificate to live in us-east-1 regardless of the
    # API's own region, and the domain-name control plane call itself is cheapest/fastest when
    # done against us-east-1 too (avoids cross-region propagation lag of the just-issued
    # certificate). Pin every AppSync call in this check to us-east-1.
    appsync = _appsync_useast1_client(ctx)
    zone_id, apex = _dns_zone(ctx)
    domain = f"{_domain_label()}.{apex}"
    cert_arn = _dns_validated_cert(ctx, zone_id, domain)

    _create_domain_name_with_retry(appsync, domain, cert_arn, description="initial-description")
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_domain_name(domainName=domain)))

    got = appsync.get_domain_name(domainName=domain)["domainNameConfig"]
    assert got["domainName"] == domain
    assert got["description"] == "initial-description"
    assert got.get("appsyncDomainName"), "expected an appsyncDomainName to be assigned"

    appsync.update_domain_name(domainName=domain, description="updated-description")
    got_after_update = appsync.get_domain_name(domainName=domain)["domainNameConfig"]
    assert got_after_update["description"] == "updated-description", (
        "UpdateDomainName change did not persist"
    )
    assert got_after_update["certificateArn"] == cert_arn

    appsync.delete_domain_name(domainName=domain)

    code, message2 = _error_code(lambda: appsync.get_domain_name(domainName=domain))
    assert code == "NotFoundException", (
        f"expected NotFoundException after delete, got {code!r} (or no error)"
    )
    assert message2 == "Domain name not found", (
        f"expected the exact NotFoundException message AWS returns, got {message2!r}"
    )


# ===== helpers =====
def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _create_domain_name_with_retry(appsync, domain, cert_arn, *, description=None, timeout_s=150.0):
    """CreateDomainName can transiently reject a just-issued, DNS-validated certificate while its
    propagation to AppSync's own validation path lags the ACM API (BadRequestException("Certificate
    does not cover domain name") or ("Certificate is invalid") even though the cert is valid), and
    can also be throttled. Retry with backoff, bounded to the check's time budget; raise (never
    skip) if the real-AWS lag genuinely never clears in time."""
    kwargs = {"domainName": domain, "certificateArn": cert_arn}
    if description is not None:
        kwargs["description"] = description

    deadline = time.monotonic() + timeout_s
    delay = 2.0
    while True:
        try:
            return appsync.create_domain_name(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "").lower()
            transient = code == "TooManyRequestsException" or (
                code == "BadRequestException"
                and ("does not cover domain name" in message or "certificate is invalid" in message)
            )
            if not transient:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "CreateDomainName did not clear the real-AWS certificate-propagation/"
                    f"throttling lag within the check's time budget (last error: {code}: {message!r})"
                )
            time.sleep(delay)
            delay = min(delay * 2, 30.0)


def _appsync_useast1_client(ctx):
    """appsync is served in us-east-1 whatever the run's region; ctx.client's overrides pin the
    endpoint and the signing region on every target."""
    return ctx.client("appsync", region="us-east-1")


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
        "this account has no DNS baseline zone: a public hosted zone delegated from its parent "
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
