"""cfn-certificate-hostedzoneid-not-covering-domain-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-certificate-hostedzoneid-not-covering-domain-rejected"
GROUP = "domain-validation"
SERVICES = ["acm", "cloudformation", "route53"]

#: The resource handler wraps the Route53 rejection; everything but the two opaque ids is ours
#: to assert exactly (CFN's own RequestToken, Route53's own Request ID in the wrapped message).
_REASON_RE = re.compile(
    r'^Resource handler returned message: '
    r'"\[RRSet with DNS name (?P<rr_name>[^\]]+?) is not permitted in zone '
    r'(?P<zone_name>[^\]]+?)\.\] '
    r'\(Service: Route53, Status Code: (?P<status_code>\d+), Request ID: [0-9a-f-]+\) '
    r'\(SDK Attempt Count: \d+\)" '
    r'\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<handler_code>\w+)\)$'
)


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); raise on deadline, never return the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


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


def _delete_hosted_zone(route53, zone_id):
    """Remove every non-NS/SOA record, then the zone itself."""
    deletable = [r for r in _record_sets(route53, zone_id) if r["Type"] not in ("NS", "SOA")]
    if deletable:
        route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [{"Action": "DELETE", "ResourceRecordSet": r} for r in deletable]
            },
        )
    route53.delete_hosted_zone(Id=zone_id)


def _delete_stack(cfn, stack_id):
    """Delete the stack and wait for DELETE_COMPLETE; idempotent on an already-deleted stack."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )


def _certificate_resource(cfn, stack_id):
    """The Certificate's own stack-resource row, or None before CFN reports one at all."""
    resources = cfn.describe_stack_resources(
        StackName=stack_id, LogicalResourceId="Certificate"
    )["StackResources"]
    return resources[0] if resources else None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A Certificate whose DomainValidationOptions HostedZoneId names a zone that does not cover
    its DomainName fails to create and its minted certificate does not survive stack deletion;
    naming a zone that does cover the domain gets ACM's own validation record written into it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-certificatemanager-certificate-domainvalidationoption.html
    """
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    acm = ctx.client("acm")

    domain = f"{ctx.unique_name('sim2real-acmhzneg-')}.com".lower()

    covering_zone = route53.create_hosted_zone(
        Name=domain,
        CallerReference=ctx.unique_name("sim2real-acmhzneg-ref-"),
        HostedZoneConfig={"Comment": "sim2real", "PrivateZone": False},
    )
    covering_zone_id = covering_zone["HostedZone"]["Id"].rsplit("/", 1)[-1]
    ctx.on_cleanup(
        _teardown(lambda: _delete_hosted_zone(route53, covering_zone_id), "NoSuchHostedZone")
    )

    other_domain = f"{ctx.unique_name('sim2real-acmhzother-')}.com".lower()
    other_zone = route53.create_hosted_zone(
        Name=other_domain,
        CallerReference=ctx.unique_name("sim2real-acmhzother-ref-"),
        HostedZoneConfig={"Comment": "sim2real", "PrivateZone": False},
    )
    other_zone_id = other_zone["HostedZone"]["Id"].rsplit("/", 1)[-1]
    ctx.on_cleanup(
        _teardown(lambda: _delete_hosted_zone(route53, other_zone_id), "NoSuchHostedZone")
    )
    other_zone_name = other_zone["HostedZone"]["Name"]

    def _template(hosted_zone_id):
        return f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Certificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: {domain}
      ValidationMethod: DNS
      DomainValidationOptions:
        - DomainName: {domain}
          HostedZoneId: {hosted_zone_id}
"""

    # --- the named zone does not cover the certificate's domain ---
    mismatched_name = ctx.unique_name("sim2real-acmhzneg-stack-")
    # DisableRollback: the default rollback deletes the Certificate before its CREATE_FAILED row
    # can be read, which is exactly the row this check needs to inspect.
    mismatched_id = cfn.create_stack(
        StackName=mismatched_name,
        TemplateBody=_template(other_zone_id),
        DisableRollback=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(_teardown(lambda: _delete_stack(cfn, mismatched_id)))

    mismatched_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=mismatched_id)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith("_COMPLETE") or s.endswith("_FAILED"),
        timeout_s=120.0, interval_s=3.0,
        description=f"stack {mismatched_name!r} reaching a terminal status",
    )
    assert mismatched_status == "CREATE_FAILED", (
        f"a Certificate whose HostedZoneId does not cover its DomainName must fail to create; "
        f"stack {mismatched_name!r} reached {mismatched_status!r}"
    )

    mismatched_resource = _certificate_resource(cfn, mismatched_id)
    assert mismatched_resource["ResourceStatus"] == "CREATE_FAILED", (
        f"expected the Certificate resource's own status to be 'CREATE_FAILED', got "
        f"{mismatched_resource['ResourceStatus']!r}"
    )
    mismatched_cert_arn = mismatched_resource.get("PhysicalResourceId")
    assert mismatched_cert_arn, (
        "a CREATE_FAILED Certificate resource must still carry the PhysicalResourceId ACM minted "
        f"before validation failed; got {mismatched_cert_arn!r}"
    )

    mismatched_cert = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=mismatched_cert_arn)["Certificate"],
        lambda c: "ResourceRecord" in c["DomainValidationOptions"][0],
        timeout_s=30.0, interval_s=2.0,
        description=f"ACM publishing a DNS validation record for {domain!r}",
    )
    rejected_challenge_name = mismatched_cert["DomainValidationOptions"][0]["ResourceRecord"]["Name"]

    reason = mismatched_resource.get("ResourceStatusReason") or ""
    reason_match = _REASON_RE.match(reason)
    assert reason_match, (
        f"expected a Route53 RRSet-rejection reason naming the mismatched zone; got {reason!r}"
    )
    assert reason_match["handler_code"] == "GeneralServiceException", (
        f"expected HandlerErrorCode 'GeneralServiceException', got "
        f"{reason_match['handler_code']!r} in {reason!r}"
    )
    assert reason_match["status_code"] == "400", (
        f"expected the wrapped Route53 call to report status 400, got "
        f"{reason_match['status_code']!r} in {reason!r}"
    )
    assert reason_match["rr_name"] == rejected_challenge_name, (
        f"expected the rejected RRSet name to be ACM's own challenge {rejected_challenge_name!r}, "
        f"got {reason_match['rr_name']!r}"
    )
    assert reason_match["zone_name"] + "." == other_zone_name, (
        f"expected the rejecting zone to be {other_zone_name!r}, got "
        f"{reason_match['zone_name']!r}."
    )

    _delete_stack(cfn, mismatched_id)
    _not_found = (
        "ResourceNotFoundException", f"Could not find certificate {mismatched_cert_arn}."
    )
    expect_error(lambda: acm.describe_certificate(CertificateArn=mismatched_cert_arn), *_not_found)

    # --- positive control: the same template naming the covering zone is accepted ---
    matching_name = ctx.unique_name("sim2real-acmhzneg-okstack-")
    matching_id = cfn.create_stack(
        StackName=matching_name,
        TemplateBody=_template(covering_zone_id),
        DisableRollback=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(_teardown(lambda: _delete_stack(cfn, matching_id)))

    matching_resource = _poll_until(
        lambda: _certificate_resource(cfn, matching_id),
        lambda r: bool(r and r.get("PhysicalResourceId")),
        timeout_s=60.0, interval_s=3.0,
        description=f"stack {matching_name!r} minting a Certificate",
    )
    matching_cert_arn = matching_resource["PhysicalResourceId"]
    matching_cert = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=matching_cert_arn)["Certificate"],
        lambda c: "ResourceRecord" in c["DomainValidationOptions"][0],
        timeout_s=30.0, interval_s=2.0,
        description=f"ACM publishing a DNS validation record for {domain!r}",
    )
    accepted_challenge = matching_cert["DomainValidationOptions"][0]["ResourceRecord"]

    written = _poll_until(
        lambda: {(r["Name"], r["Type"]): r for r in _record_sets(route53, covering_zone_id)},
        lambda rrsets: (accepted_challenge["Name"], "CNAME") in rrsets,
        timeout_s=90.0, interval_s=3.0,
        description=(
            f"CloudFormation writing the validation CNAME {accepted_challenge['Name']!r} into "
            f"the covering zone {covering_zone_id}"
        ),
    )[(accepted_challenge["Name"], "CNAME")]
    assert [rr["Value"] for rr in written["ResourceRecords"]] == [accepted_challenge["Value"]], (
        f"expected the written CNAME to target ACM's own challenge value "
        f"{accepted_challenge['Value']!r}; zone holds "
        f"{[rr['Value'] for rr in written['ResourceRecords']]!r}"
    )

    _delete_stack(cfn, matching_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
