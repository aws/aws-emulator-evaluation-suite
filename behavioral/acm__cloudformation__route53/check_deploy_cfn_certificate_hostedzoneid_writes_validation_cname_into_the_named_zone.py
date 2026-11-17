"""deploy-cfn-certificate-hostedzoneid-writes-validation-cname-into-the-named-zone."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-certificate-hostedzoneid-writes-validation-cname-into-the-named-zone"
GROUP = "deploy"
SERVICES = ["acm", "cloudformation", "route53"]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); raise on deadline, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _record_sets(route53, zone_id):
    """Every record set in a hosted zone, following the paginated cursor."""
    sets, kwargs = [], {"HostedZoneId": zone_id}
    while True:
        page = route53.list_resource_record_sets(**kwargs)
        sets.extend(page["ResourceRecordSets"])
        if not page["IsTruncated"]:
            return sets
        kwargs["StartRecordName"] = page["NextRecordName"]
        kwargs["StartRecordType"] = page["NextRecordType"]


def _empty_and_delete_zone(route53, zone_id):
    """Delete every non-NS/SOA record, then the zone itself; a not-found zone is already gone."""
    deletable = [r for r in _record_sets(route53, zone_id) if r["Type"] not in ("NS", "SOA")]
    if deletable:
        route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": r}
                                      for r in deletable]},
        )
    try:
        route53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _delete_stack(cfn, stack_name):
    """Delete the stack and wait for DELETE_COMPLETE; a DELETE_FAILED or stalled delete raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


def _wait_for_stack_resource_physical_id(cfn, stack_name, logical_id, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cfn.describe_stack_resources(StackName=stack_name, LogicalResourceId=logical_id)
        for resource in resp.get("StackResources", []):
            if resource.get("PhysicalResourceId"):
                return resource["PhysicalResourceId"], resource.get("ResourceStatus"), \
                    resource.get("ResourceStatusReason")
        time.sleep(interval_s)
    raise AssertionError(
        f"resource {logical_id} in stack {stack_name} never received a physical id within "
        f"{timeout_s}s"
    )


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CertificateManager::Certificate naming a HostedZoneId the caller owns
    is accepted and its DNS validation CNAME, exactly as DescribeCertificate reports it, is written
    into that hosted zone.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-certificatemanager-certificate-domainvalidationoption.md
    """
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    acm = ctx.client("acm")

    domain = f"{ctx.unique_name('sim2realacmhz')}.com".lower()

    zone = route53.create_hosted_zone(
        Name=domain,
        CallerReference=ctx.unique_name("sim2real-acmhz-ref-"),
        HostedZoneConfig={"Comment": "sim2real", "PrivateZone": False},
    )
    zone_id = zone["HostedZone"]["Id"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _empty_and_delete_zone(route53, zone_id))
    route53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id, AddTags=[{"Key": "sim2real", "Value": CHECK}]
    )

    stack_name = ctx.unique_name("sim2real-acmhz-stack-")
    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Certificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: {domain}
      ValidationMethod: DNS
      DomainValidationOptions:
        - DomainName: {domain}
          HostedZoneId: {zone_id}
"""
    # Registered SECOND so it runs FIRST (LIFO): the stack's certificate and its auto-written
    # CNAME must both be gone before the hosted zone can be emptied and deleted.
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    cert_arn, resource_status, reason = _wait_for_stack_resource_physical_id(
        cfn, stack_name, "Certificate", timeout_s=90.0, interval_s=3.0
    )
    assert resource_status != "CREATE_FAILED", (
        f"the Certificate resource must not fail at create on its HostedZoneId property; got "
        f"ResourceStatus={resource_status!r} reason={reason!r}"
    )

    described = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda d: d.get("DomainValidationOptions")
        and "ResourceRecord" in d["DomainValidationOptions"][0],
        timeout_s=60.0, interval_s=2.0,
        description=f"DescribeCertificate publishing a DNS validation record for {domain!r}",
    )
    assert described["DomainName"] == domain, (
        f"expected DescribeCertificate DomainName={domain!r}, got {described['DomainName']!r}"
    )
    option = described["DomainValidationOptions"][0]
    assert option["DomainName"] == domain, (
        f"expected DomainValidationOptions[0].DomainName={domain!r}, got {option['DomainName']!r}"
    )
    assert option["ValidationMethod"] == "DNS", (
        f"expected DomainValidationOptions[0].ValidationMethod='DNS', got "
        f"{option['ValidationMethod']!r}"
    )
    challenge = option["ResourceRecord"]
    assert challenge["Type"] == "CNAME", (
        f"ACM's DNS challenge must be a CNAME; got {challenge['Type']!r}"
    )

    found = _poll_until(
        lambda: {(r["Name"], r["Type"]): r for r in _record_sets(route53, zone_id)},
        lambda rrsets: (challenge["Name"], "CNAME") in rrsets,
        timeout_s=60.0, interval_s=3.0,
        description=(
            f"CloudFormation writing the validation CNAME {challenge['Name']!r} into hosted "
            f"zone {zone_id}"
        ),
    )
    published = found[(challenge["Name"], "CNAME")]
    assert [rr["Value"] for rr in published["ResourceRecords"]] == [challenge["Value"]], (
        f"the CNAME CloudFormation wrote into zone {zone_id} must target exactly what "
        f"DescribeCertificate asked for; zone holds "
        f"{[rr['Value'] for rr in published['ResourceRecords']]!r}, ACM asked for "
        f"{challenge['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
