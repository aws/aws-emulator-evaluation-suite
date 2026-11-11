"""api-association-get-not-found-when-unassociated."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-association-get-not-found-when-unassociated"
GROUP = "error-semantics"
SERVICES = ["appsync"]



@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """GetApiAssociation for a domain with no association returns NotFoundException, not an
    empty success; the identical call succeeds once AssociateApi actually links an Api."""
    appsync = ctx.client("appsync")
    # AppSync's CreateDomainName accepts only a certificate ACM itself issued, so the domain
    # lives under a zone that can DNS-validate one.
    zone_id, apex = _dns_zone(ctx)
    domain_name = f"{_domain_label()}.{apex}"
    cert_arn = _dns_validated_cert(ctx, zone_id, domain_name)

    _create_domain_name_with_retry(appsync, domainName=domain_name, certificateArn=cert_arn)
    ctx.on_cleanup(lambda: appsync.delete_domain_name(domainName=domain_name))

    # The domain was just created and never associated with any Api.
    code, message = _error_code(lambda: appsync.get_api_association(domainName=domain_name))
    assert code == "NotFoundException", (
        f"expected NotFoundException for an unassociated domain, got {code!r}"
    )
    assert message == "Domain name is not associated.", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )

    # Positive control: once a real association exists, the identical GetApiAssociation call
    # succeeds -- without this, the NotFoundException above could just as easily mean
    # "GetApiAssociation always fails" as "fails only while unassociated".
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-assoc-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.associate_api(domainName=domain_name, apiId=api_id)
    ctx.on_cleanup(lambda: _safe_disassociate(appsync, domain_name))

    association = _wait_for(
        lambda: appsync.get_api_association(domainName=domain_name)["apiAssociation"],
        lambda a: a["associationStatus"] in ("SUCCESS", "FAILED"),
        600,
        f"association of {api_id} to {domain_name} to leave PROCESSING",
    )
    assert association["associationStatus"] == "SUCCESS", (
        f"positive control: association did not reach SUCCESS, got {association!r}"
    )
    assert association["apiId"] == api_id, (
        f"positive control: GetApiAssociation named the wrong Api, got {association!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_disassociate(appsync, domain_name: str, timeout_s: float = 600.0) -> None:
    """Disassociate, then wait for it to actually clear: a domain mid-PROCESSING rejects
    DeleteDomainName and holds its certificate, so a fire-and-forget DisassociateApi would
    leave both cleanups to fail right behind it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            appsync.disassociate_api(domainName=domain_name)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConcurrentModificationException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)

    while time.monotonic() < deadline:
        try:
            appsync.get_api_association(domainName=domain_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"disassociation of {domain_name} did not clear within {timeout_s}s")


def _create_domain_name_with_retry(appsync, timeout_s: float = 120.0, interval_s: float = 5.0, **kwargs):
    """CreateDomainName, retried while AppSync's own validation of a just-issued certificate
    trails ACM's ISSUED status (BadRequestException "Certificate is invalid"); any other error
    raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return appsync.create_domain_name(**kwargs)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            invalid = error.get("Code") == "BadRequestException" and "Certificate is invalid" in error.get("Message", "")
            if not invalid or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)

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
