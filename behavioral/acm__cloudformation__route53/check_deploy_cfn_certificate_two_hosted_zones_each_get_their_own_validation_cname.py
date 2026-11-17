"""deploy-cfn-certificate-two-hosted-zones-each-get-their-own-validation-cname."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-certificate-two-hosted-zones-each-get-their-own-validation-cname"
GROUP = "deploy"
SERVICES = ["acm", "cloudformation", "route53"]


def _until(fetch, satisfied, *, budget_s, interval_s, what):
    """Return ``fetch()`` once ``satisfied`` of it holds; raise naming the last value otherwise."""
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = fetch()
        if satisfied(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} did not hold within {budget_s}s; last seen {last!r}")


def _zone_cname_index(route53, zone_id):
    """``{record-name: ResourceRecordSet}`` for every CNAME in ``zone_id``, following pagination."""
    index, kwargs = {}, {"HostedZoneId": zone_id}
    while True:
        page = route53.list_resource_record_sets(**kwargs)
        for rrset in page["ResourceRecordSets"]:
            if rrset["Type"] == "CNAME":
                index[rrset["Name"]] = rrset
        if not page["IsTruncated"]:
            return index
        kwargs["StartRecordName"] = page["NextRecordName"]
        kwargs["StartRecordType"] = page["NextRecordType"]


def _retire_zone(route53, zone_id):
    """Strip every non-apex record from ``zone_id`` and delete it; already-gone is fine."""
    try:
        others = [
            r
            for r in route53.list_resource_record_sets(HostedZoneId=zone_id)["ResourceRecordSets"]
            if r["Type"] not in ("NS", "SOA")
        ]
        if others:
            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Changes": [{"Action": "DELETE", "ResourceRecordSet": r} for r in others]
                },
            )
        route53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _retire_stack(cfn, stack_name):
    """Delete the stack and block until it reports DELETE_COMPLETE; raise on any other end state."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


def _certificate_physical_id(cfn, stack_name, *, budget_s):
    """``(physical_id, status, reason)`` once the Certificate resource reports one."""

    def peek():
        resp = cfn.describe_stack_resources(StackName=stack_name, LogicalResourceId="Certificate")
        for r in resp["StackResources"]:
            if r.get("PhysicalResourceId"):
                return r["PhysicalResourceId"], r["ResourceStatus"], r.get("ResourceStatusReason")
        return None

    return _until(
        peek,
        lambda v: v is not None,
        budget_s=budget_s,
        interval_s=3.0,
        what="the Certificate resource reporting a physical id",
    )


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Certificate spanning two owned zones, with a DomainValidationOptions entry per domain
    naming that domain's bare HostedZoneId, writes each zone exactly the DNS validation CNAME
    DescribeCertificate reports for its own domain, while PENDING_VALIDATION."""
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    acm = ctx.client("acm")

    # ACM answers FailureReason=ADDITIONAL_VERIFICATION_REQUIRED for every IANA documentation
    # TLD (.test, .invalid, .example) before a DNS challenge is ever generated, and Route 53
    # refuses to create a hosted zone for example.com itself; a generated, unregistrable label
    # under a generic TLD is the only domain shape ACM will actually open DNS validation for.
    # real-data: ACM structurally blocks every reserved documentation TLD, so no allowed test
    # domain can exercise DNS validation; this label is unique per run and resolves nowhere.
    primary_domain = f"{ctx.unique_name('sim2realacmdva')}.com".lower()
    san_domain = f"{ctx.unique_name('sim2realacmdvb')}.com".lower()

    primary_zone = route53.create_hosted_zone(
        Name=primary_domain,
        CallerReference=ctx.unique_name("sim2real-acmdv-ref-"),
        HostedZoneConfig={"Comment": "sim2real", "PrivateZone": False},
    )
    primary_zone_id = primary_zone["HostedZone"]["Id"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda zid=primary_zone_id: _retire_zone(route53, zid))

    san_zone = route53.create_hosted_zone(
        Name=san_domain,
        CallerReference=ctx.unique_name("sim2real-acmdv-ref-"),
        HostedZoneConfig={"Comment": "sim2real", "PrivateZone": False},
    )
    san_zone_id = san_zone["HostedZone"]["Id"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda zid=san_zone_id: _retire_zone(route53, zid))

    stack_name = ctx.unique_name("sim2real-acmdv-stack-")
    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Certificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: {primary_domain}
      SubjectAlternativeNames:
        - {san_domain}
      ValidationMethod: DNS
      DomainValidationOptions:
        - DomainName: {primary_domain}
          HostedZoneId: {primary_zone_id}
        - DomainName: {san_domain}
          HostedZoneId: {san_zone_id}
"""
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda sn=stack_name: _retire_stack(cfn, sn))

    cert_arn, resource_status, reason = _certificate_physical_id(cfn, stack_name, budget_s=90.0)
    assert resource_status != "CREATE_FAILED", (
        f"the Certificate resource must accept two DomainValidationOptions entries, one per "
        f"owned zone; got ResourceStatus={resource_status!r} reason={reason!r}"
    )

    described = _until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda d: len(d.get("DomainValidationOptions") or []) == 2
        and all("ResourceRecord" in opt for opt in d["DomainValidationOptions"]),
        budget_s=60.0,
        interval_s=2.0,
        what="DescribeCertificate publishing a DNS challenge for both domains",
    )
    assert described["DomainName"] == primary_domain, (
        f"expected DescribeCertificate DomainName={primary_domain!r}, got "
        f"{described['DomainName']!r}"
    )
    assert set(described["SubjectAlternativeNames"]) == {primary_domain, san_domain}, (
        f"expected SubjectAlternativeNames to cover {{{primary_domain!r}, {san_domain!r}}}, got "
        f"{described['SubjectAlternativeNames']!r}"
    )
    assert described["Status"] == "PENDING_VALIDATION", (
        f"expected Status='PENDING_VALIDATION' while validation is outstanding, got "
        f"{described['Status']!r}"
    )

    options_by_domain = {opt["DomainName"]: opt for opt in described["DomainValidationOptions"]}
    assert set(options_by_domain) == {primary_domain, san_domain}, (
        f"expected one DomainValidationOptions entry per domain {[primary_domain, san_domain]!r}, "
        f"got entries for {sorted(options_by_domain)!r}"
    )
    for domain, option in options_by_domain.items():
        assert option["ValidationMethod"] == "DNS", (
            f"expected {domain!r}'s ValidationMethod='DNS', got {option['ValidationMethod']!r}"
        )
        assert option["ResourceRecord"]["Type"] == "CNAME", (
            f"expected {domain!r}'s DNS challenge to be a CNAME, got "
            f"{option['ResourceRecord']['Type']!r}"
        )

    primary_challenge = options_by_domain[primary_domain]["ResourceRecord"]
    san_challenge = options_by_domain[san_domain]["ResourceRecord"]

    primary_records = _until(
        lambda: _zone_cname_index(route53, primary_zone_id),
        lambda idx: primary_challenge["Name"] in idx,
        budget_s=60.0,
        interval_s=3.0,
        what=f"CloudFormation writing {primary_domain!r}'s validation CNAME into its own zone",
    )
    san_records = _until(
        lambda: _zone_cname_index(route53, san_zone_id),
        lambda idx: san_challenge["Name"] in idx,
        budget_s=60.0,
        interval_s=3.0,
        what=f"CloudFormation writing {san_domain!r}'s validation CNAME into its own zone",
    )

    primary_values = [
        rr["Value"] for rr in primary_records[primary_challenge["Name"]]["ResourceRecords"]
    ]
    assert primary_values == [primary_challenge["Value"]], (
        f"zone for {primary_domain!r} must hold exactly the CNAME value ACM asked for; zone has "
        f"{primary_values!r}, ACM asked for {primary_challenge['Value']!r}"
    )
    san_values = [rr["Value"] for rr in san_records[san_challenge["Name"]]["ResourceRecords"]]
    assert san_values == [san_challenge["Value"]], (
        f"zone for {san_domain!r} must hold exactly the CNAME value ACM asked for; zone has "
        f"{san_values!r}, ACM asked for {san_challenge['Value']!r}"
    )

    assert san_challenge["Name"] not in primary_records, (
        f"the zone for {primary_domain!r} must not receive {san_domain!r}'s validation CNAME "
        f"{san_challenge['Name']!r}"
    )
    assert primary_challenge["Name"] not in san_records, (
        f"the zone for {san_domain!r} must not receive {primary_domain!r}'s validation CNAME "
        f"{primary_challenge['Name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
