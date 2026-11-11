"""deploy-stack-deletion-removes-certificate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-deletion-removes-certificate"
GROUP = "deploy"
SERVICES = ["acm"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
Resources:
  Cert:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: !Ref DomainNameParam
      ValidationMethod: DNS
"""


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting the CloudFormation stack that owns an AWS::CertificateManager::Certificate
    causes DescribeCertificate to return ResourceNotFoundException -- proving the underlying
    ACM resource, not just the stack record, was torn down."""
    cfn = ctx.client("cloudformation")
    acm = ctx.client("acm")

    stack_name = ctx.unique_name("sim2real-acm-cfn-del-")
    domain = f"{_dns_label(ctx.unique_name('sim2real-acm-del'))}.example.com"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "DomainNameParam", "ParameterValue": domain}],
        OnFailure="DO_NOTHING",
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: cfn.delete_stack(StackName=stack_name)))

    cert_arn = _poll_until(
        lambda: _physical_id(cfn, stack_name, "Cert"),
        lambda v: v is not None,
        timeout_s=120,
        interval_s=3,
    )
    # sanity: the certificate genuinely exists before we delete the stack
    acm.describe_certificate(CertificateArn=cert_arn)

    cfn.delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_exists(cfn, stack_name),
        lambda exists: not exists,
        timeout_s=180,
        interval_s=5,
    )

    expected_message = f"Could not find certificate {cert_arn}."
    code, message = _error_code(lambda: acm.describe_certificate(CertificateArn=cert_arn))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeCertificate({cert_arn}) to fail with ResourceNotFoundException "
        f"after the owning stack was deleted, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The dead ARN must not just be unreadable -- it must be unusable: a mutation
    # against it fails the same way, not with some other error class.
    mutate_code, mutate_message = _error_code(
        lambda: acm.add_tags_to_certificate(
            CertificateArn=cert_arn, Tags=[{"Key": "sim2real-post-delete", "Value": "x"}]
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected AddTagsToCertificate({cert_arn}) to fail with ResourceNotFoundException "
        f"after the owning stack was deleted, got {mutate_code!r}"
    )
    assert mutate_message == expected_message, f"expected message {expected_message!r}, got {mutate_message!r}"


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


def _stack_exists(cfn, stack_name: str) -> bool:
    try:
        resp = cfn.describe_stacks(StackName=stack_name)
    except ClientError:
        return False
    stacks = resp.get("Stacks", [])
    if not stacks:
        return False
    return stacks[0]["StackStatus"] != "DELETE_COMPLETE"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
