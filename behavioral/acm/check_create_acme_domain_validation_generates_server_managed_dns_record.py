"""create-acme-domain-validation-generates-server-managed-dns-record."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-acme-domain-validation-generates-server-managed-dns-record"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """ACM computes the DNS challenge record server-side (the request has no field for it), scoped
    to the validated domain, and repeated Describes return the same record rather than
    regenerating it per read."""
    acm = ctx.client("acm")
    endpoint_arn = _create_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)

    domain_name, hosted_zone_id = _create_hosted_zone(ctx)

    dv_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain_name,
        PrevalidationOptions={
            "DnsPrevalidation": {
                "DomainScope": {
                    "ExactDomain": "ENABLED",
                    "Subdomains": "DISABLED",
                    "Wildcards": "DISABLED",
                },
                "HostedZoneId": hosted_zone_id,
            }
        },
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=dv_arn))

    first = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
        "AcmeDomainValidation"
    ]
    # VALIDATING lasts seconds on AWS; the record may already have settled by the first read.
    assert first["Status"] in ("VALIDATING", "VALID", "INVALID"), f"unexpected initial status: {first['Status']}"
    assert first.get("PrevalidationType") == "DNS", (
        f"unexpected PrevalidationType: {first.get('PrevalidationType')!r} full={first!r}"
    )

    record = _wait_for_resource_record(acm, dv_arn)
    assert record["Type"] == "CNAME", f"unexpected server-computed record Type: {record['Type']!r}"
    assert record["Name"], "server-computed DNS record Name must not be empty"
    assert record["Value"], "server-computed DNS record Value must not be empty"
    # The record name is scoped to the validated domain, not an arbitrary token.
    assert record["Name"].rstrip(".").endswith(domain_name), (
        f"record Name {record['Name']!r} is not scoped to the validated domain {domain_name!r}"
    )
    # The caller never supplied a record Name/Value -- they cannot be an echo of
    # any client input because the request shape has no such field.
    assert record["Name"] != domain_name, "record Name must not simply equal the bare domain"

    second = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
        "AcmeDomainValidation"
    ]
    record_again = second["PrevalidationDetails"]["DnsPrevalidation"]["ResourceRecord"]
    assert record_again["Name"] == record["Name"], "record Name changed across repeated Describes"
    assert record_again["Value"] == record["Value"], "record Value changed across repeated Describes"


def _create_hosted_zone(ctx: Any) -> tuple[str, str]:
    """Create a public Route 53 hosted zone for the DNS challenge CNAME; without a
    HostedZoneId, ACM never populates ResourceRecord."""
    route53 = ctx.client("route53")
    zone_name = f"{ctx.unique_name('sim2real-acm-dv-').lower()}.com"
    resp = route53.create_hosted_zone(
        Name=zone_name,
        CallerReference=ctx.unique_name("sim2real-acm-dv-zone-"),
    )
    zone_id = resp["HostedZone"]["Id"].split("/")[-1]
    ctx.on_cleanup(lambda: _delete_hosted_zone(route53, zone_id, zone_name))
    return zone_name.rstrip("."), zone_id


def _delete_hosted_zone(route53: Any, zone_id: str, zone_name: str, timeout_s: float = 120.0) -> None:
    """Delete the zone once the challenge CNAME ACM writes into it is gone. ACM writes and removes
    that record on its own, so each round deletes every non-apex-NS/SOA record set it lists and
    retries until DeleteHostedZone stops answering HostedZoneNotEmpty; any other error raises."""
    from botocore.exceptions import ClientError

    apex = zone_name.rstrip(".") + "."
    deadline = time.monotonic() + timeout_s
    while True:
        for rrset in _list_record_sets(route53, zone_id):
            if rrset["Name"] == apex and rrset["Type"] in ("NS", "SOA"):
                continue
            try:
                route53.change_resource_record_sets(
                    HostedZoneId=zone_id,
                    ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrset}]},
                )
            except ClientError as exc:
                # The record set changed or vanished between the list and the delete.
                if exc.response["Error"]["Code"] != "InvalidChangeBatch":
                    raise
        try:
            route53.delete_hosted_zone(Id=zone_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "HostedZoneNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _list_record_sets(route53: Any, zone_id: str) -> list[dict]:
    paginator = route53.get_paginator("list_resource_record_sets")
    return [r for page in paginator.paginate(HostedZoneId=zone_id) for r in page["ResourceRecordSets"]]


def _wait_for_resource_record(acm: Any, dv_arn: str, timeout_s: float = 240.0, interval_s: float = 5.0) -> dict:
    """Poll until the asynchronously computed DNS challenge record appears in
    PrevalidationDetails.DnsPrevalidation; it is absent right after the create returns."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_domain_validation(AcmeDomainValidationArn=dv_arn)[
            "AcmeDomainValidation"
        ]
        record = last["PrevalidationDetails"]["DnsPrevalidation"].get("ResourceRecord")
        if record:
            return record
        time.sleep(interval_s)
    raise AssertionError(
        f"ResourceRecord never materialized for {dv_arn} within {timeout_s}s, last={last}"
    )

def _create_endpoint(ctx: Any) -> str:
    acm = ctx.client("acm")
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acme-ep-")}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx: Any, arn: str, timeout_s: float = 180.0) -> dict:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        status = endpoint["Status"]
        if status == "ACTIVE":
            return endpoint
        if status == "FAILED":
            raise AssertionError(f"ACME endpoint {arn} failed: {endpoint.get('FailureReason')}")
        time.sleep(3)
    raise AssertionError(f"ACME endpoint {arn} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
