"""deploy-cfn-certificate-validation-behaves."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-certificate-validation-behaves"
GROUP = "deploy"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-created AWS::CertificateManager::Certificate is visible through
    DescribeCertificate and ListCertificates as PENDING_VALIDATION with one DNS validation option,
    while its stack resource is still CREATE_IN_PROGRESS and the stack never CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    acm = ctx.client("acm")

    # A random ".com" name, not an RFC 2606 reserved one: ACM drives a reserved-domain request to
    # FAILED within seconds (and CloudFormation then rolls the stack back), while this one stays
    # PENDING_VALIDATION for its 72-hour window and the resource stays CREATE_IN_PROGRESS.
    domain = f"{ctx.unique_name('sim2realacmval').rstrip('-')}.com".lower()
    stack_name = ctx.unique_name("sim2real-acm-valstack-")
    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Certificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: {domain}
      ValidationMethod: DNS
"""
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # The domain is not in Route 53, so it can never validate and the stack never completes.
    cert_arn, resource_status, reason = _wait_for_stack_resource_physical_id(
        ctx, stack_name, "Certificate", timeout_s=60.0, interval_s=1.0
    )
    assert resource_status == "CREATE_IN_PROGRESS", (
        f"expected the Certificate resource to still be CREATE_IN_PROGRESS (unvalidated) "
        f"when we first observed its physical id, got status={resource_status!r} "
        f"reason={reason!r}"
    )

    described = _poll_describable(acm, cert_arn, timeout_s=20.0, interval_s=1.0)
    assert described is not None, (
        f"certificate {cert_arn} stayed unreachable via DescribeCertificate for 20s after "
        f"CloudFormation reported its physical id"
    )

    assert described["DomainName"] == domain, (
        f"expected DescribeCertificate DomainName={domain!r}, got {described['DomainName']!r}"
    )
    assert described["Status"] == "PENDING_VALIDATION", (
        f"expected Status='PENDING_VALIDATION', got {described['Status']!r}"
    )

    domain_options = described["DomainValidationOptions"]
    assert len(domain_options) == 1, (
        f"expected exactly 1 DomainValidationOptions entry, got {len(domain_options)}: {domain_options!r}"
    )
    assert domain_options[0]["DomainName"] == domain, (
        f"expected DomainValidationOptions[0].DomainName={domain!r}, got {domain_options[0]['DomainName']!r}"
    )
    assert domain_options[0]["ValidationStatus"] == "PENDING_VALIDATION", (
        f"expected DomainValidationOptions[0].ValidationStatus='PENDING_VALIDATION', "
        f"got {domain_options[0]['ValidationStatus']!r}"
    )
    assert domain_options[0]["ValidationMethod"] == "DNS", (
        f"expected DomainValidationOptions[0].ValidationMethod='DNS', "
        f"got {domain_options[0]['ValidationMethod']!r}"
    )

    listed = _poll_list_certificates_contains(acm, cert_arn, timeout_s=20.0, interval_s=2.0)
    assert listed, f"certificate {cert_arn} never appeared in ListCertificates(PENDING_VALIDATION)"

    stack_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert stack_status != "CREATE_COMPLETE", f"unexpected stack_status={stack_status!r}"


def _delete_stack(cfn, stack_name):
    """Delete the stack and wait for DELETE_COMPLETE; a DELETE_FAILED or stalled delete raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


def _poll_list_certificates_contains(acm, cert_arn, *, timeout_s=20.0, interval_s=2.0):
    """Poll every page of ListCertificates(PENDING_VALIDATION); it can lag DescribeCertificate for
    a new cert."""
    deadline = time.monotonic() + timeout_s
    paginator = acm.get_paginator("list_certificates")
    while time.monotonic() < deadline:
        for page in paginator.paginate(CertificateStatuses=["PENDING_VALIDATION"]):
            if any(c["CertificateArn"] == cert_arn for c in page["CertificateSummaryList"]):
                return True
        time.sleep(interval_s)
    return False


def _poll_describable(acm, cert_arn, *, timeout_s, interval_s):
    """DescribeCertificate once it stops answering ResourceNotFoundException, or None."""
    deadline = time.monotonic() + timeout_s
    while True:
        described = _describe_or_none(acm, cert_arn)
        if described is not None or time.monotonic() >= deadline:
            return described
        time.sleep(interval_s)


def _describe_or_none(acm, cert_arn):
    """DescribeCertificate, or None on ResourceNotFoundException (briefly returned right after
    CloudFormation reports the physical id)."""
    from botocore.exceptions import ClientError

    try:
        return acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _wait_for_stack_resource_physical_id(ctx, stack_name, logical_id, timeout_s=90.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cfn.describe_stack_resources(StackName=stack_name, LogicalResourceId=logical_id)
        for resource in resp.get("StackResources", []):
            if resource.get("PhysicalResourceId"):
                return (
                    resource["PhysicalResourceId"],
                    resource.get("ResourceStatus"),
                    resource.get("ResourceStatusReason"),
                )
        time.sleep(interval_s)
    raise AssertionError(
        f"resource {logical_id} in stack {stack_name} never received a physical id within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
