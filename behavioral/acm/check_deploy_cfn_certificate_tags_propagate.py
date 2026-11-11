"""deploy-cfn-certificate-tags-propagate."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-certificate-tags-propagate"
GROUP = "deploy"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags declared on a CloudFormation-deployed AWS::CertificateManager::Certificate
    resource are visible via ListTagsForResource exactly as specified in the template
    -- neither dropped, renamed, nor merged with unrelated tags."""
    cfn = ctx.client("cloudformation")
    acm = ctx.client("acm")

    domain = f"{ctx.unique_name('sim2realacmtag').rstrip('-')}.example.com".lower()
    stack_name = ctx.unique_name("sim2real-acm-tagstack-")
    owner_value = ctx.unique_name("owner-")
    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Certificate:
    Type: AWS::CertificateManager::Certificate
    Properties:
      DomainName: {domain}
      ValidationMethod: DNS
      Tags:
        - Key: sim2real-owner
          Value: {owner_value}
        - Key: sim2real-batch
          Value: acm-batch-05
"""
    deleted = [False]
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: None if deleted[0] else cfn.delete_stack(StackName=stack_name))

    cert_arn = _wait_for_stack_resource_physical_id(ctx, stack_name, "Certificate", timeout_s=90.0)

    described = acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    assert described["DomainName"] == domain

    # ACM certificates are tagged/queried via the certificate-specific tagging APIs, not
    # the generic ListTagsForResource (which explicitly rejects certificate ARNs with a
    # ValidationException on real AWS: "only supports non-certificate resource").
    tags = {t["Key"]: t["Value"] for t in acm.list_tags_for_certificate(CertificateArn=cert_arn)["Tags"]}
    assert tags.get("sim2real-owner") == owner_value
    assert tags.get("sim2real-batch") == "acm-batch-05"
    sim2real_tags = {k: v for k, v in tags.items() if k.startswith("sim2real-")}
    assert sim2real_tags == {
        "sim2real-owner": owner_value,
        "sim2real-batch": "acm-batch-05",
    }, f"unexpected sim2real-* tags: {sim2real_tags!r} (full tag set: {tags!r})"

    # Overly-permissive boundary: the generic resource-tagging ListTagsForResource must
    # reject a certificate ARN with a specific ValidationException, not silently succeed
    # or return an empty/garbage tag set.
    code, message = _error_code(lambda: acm.list_tags_for_resource(ResourceArn=cert_arn))
    assert code == "ValidationException", f"expected ValidationException for cert ARN, got {code!r}"
    expected_message = (
        f"ListTagsForResource only supports non-certificate resource types. Resource {cert_arn} "
        "is a certificate resource. Use ListTagsForCertificate API instead."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The domain is not hosted in Route 53, so DNS validation can never complete and
    # CloudFormation gives up and rolls the stack back (deleting the certificate) rather
    # than reaching CREATE_COMPLETE. Drive the teardown explicitly and prove the
    # certificate is genuinely gone from the ACM data plane afterward -- not merely that
    # CloudFormation's own bookkeeping says so.
    final_status = _wait_for_stack_terminal_status(cfn, stack_name, timeout_s=150.0, interval_s=5.0)
    assert final_status == "ROLLBACK_COMPLETE", (
        f"expected the unvalidatable DNS certificate to force a stack rollback, "
        f"got stack_status={final_status!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 75}
    )
    deleted[0] = True

    code, message = _error_code(lambda: acm.describe_certificate(CertificateArn=cert_arn))
    assert code == "ResourceNotFoundException", (
        f"expected certificate {cert_arn} to be gone after stack teardown, got code={code!r}"
    )
    expected_message = f"Could not find certificate {cert_arn}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_stack_terminal_status(cfn, stack_name, timeout_s=150.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    in_progress = {"CREATE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS", "DELETE_IN_PROGRESS"}
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status not in in_progress:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never left an in-progress status within {timeout_s}s")


def _wait_for_stack_resource_physical_id(ctx, stack_name, logical_id, timeout_s=90.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cfn.describe_stack_resources(StackName=stack_name, LogicalResourceId=logical_id)
        for resource in resp.get("StackResources", []):
            if resource.get("PhysicalResourceId"):
                return resource["PhysicalResourceId"]
        time.sleep(interval_s)
    raise AssertionError(
        f"resource {logical_id} in stack {stack_name} never received a physical id within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
