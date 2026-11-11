"""deploy-acm-certificate-stack-behaves."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-acm-certificate-stack-behaves"
GROUP = "deploy"
SERVICES = ["acm"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
  SanParam:
    Type: String
  TagValueParam:
    Type: String
Resources:
  Cert:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: !Ref DomainNameParam
      SubjectAlternativeNames:
        - !Ref SanParam
      ValidationMethod: DNS
      Tags:
        - Key: sim2real-check
          Value: !Ref TagValueParam
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::CertificateManager::Certificate yields a certificate whose
    DomainName, SANs and tags match the template parameters."""
    cfn = ctx.client("cloudformation")
    acm = ctx.client("acm")

    stack_name = ctx.unique_name("sim2real-acm-cfn-")
    domain = f"{_dns_label(ctx.unique_name('sim2real-acm'))}.example.com"
    san = f"www.{domain}"
    tag_value = f"deploy-behav-{uuid.uuid4().hex[:12]}"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "DomainNameParam", "ParameterValue": domain},
            {"ParameterKey": "SanParam", "ParameterValue": san},
            {"ParameterKey": "TagValueParam", "ParameterValue": tag_value},
        ],
        OnFailure="DO_NOTHING",
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: cfn.delete_stack(StackName=stack_name)))

    # No wait for CREATE_COMPLETE: a DNS-validated cert never completes without owning the
    # domain, but RequestCertificate has already run once the PhysicalResourceId is assigned.
    cert_arn = _poll_until(
        lambda: _physical_id(cfn, stack_name, "Cert"),
        lambda v: v is not None,
        timeout_s=120,
        interval_s=3,
    )

    cert = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert cert["DomainName"] == domain, (
        f"expected DomainName={domain!r} from the template parameter, got {cert['DomainName']!r}"
    )
    actual_sans = set(cert["SubjectAlternativeNames"])
    expected_sans = {domain, san}
    assert actual_sans == expected_sans, (
        f"expected SubjectAlternativeNames={expected_sans!r}, got {actual_sans!r}"
    )

    tags = acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get("sim2real-check") == tag_value, (
        f"expected tag sim2real-check={tag_value!r}, got {tag_map.get('sim2real-check')!r} "
        f"(full tag set: {tag_map!r})"
    )


def _dns_label(name: str) -> str:
    label = "".join(c if c.isalnum() else "-" for c in name.lower())
    return label.strip("-") or "sim2real"


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _physical_id(cfn, stack_name: str, logical_id: str):
    try:
        resp = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
    except ClientError:
        return None
    return resp.get("StackResourceDetail", {}).get("PhysicalResourceId")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
