"""deploy-acme-endpoint-via-cloudformation-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-acme-endpoint-via-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ACME endpoint created by a CloudFormation stack is describable through ACM while
    ACTIVE, and gone from ACM once the stack deletion completes."""
    acm = ctx.client("acm")
    _require_acme_api(acm)
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-acm-acmeep-")
    template = json.dumps(
        {
            "Resources": {
                "Endpoint": {
                    "Type": "AWS::CertificateManager::AcmeEndpoint",
                    "Properties": {
                        "AuthorizationBehavior": "PRE_APPROVED",
                        "CertificateAuthority": {
                            "PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["RSA_2048"]}
                        },
                    },
                }
            },
            "Outputs": {
                "EndpointArn": {"Value": {"Fn::GetAtt": ["Endpoint", "AcmeEndpointArn"]}},
            },
        }
    )
    deleted = [False]
    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: None if deleted[0] else cfn.delete_stack(StackName=stack_name))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    endpoint_arn = outputs["EndpointArn"]

    # Data-plane describe: the endpoint must be real, not just a CFN-reported success.
    desc = acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]
    assert desc["AuthorizationBehavior"] == "PRE_APPROVED", (
        f"expected AuthorizationBehavior PRE_APPROVED, got {desc['AuthorizationBehavior']!r}"
    )

    status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert status == "ACTIVE", f"CFN-created endpoint reached {status}, expected ACTIVE"

    # Delete through the stack, then confirm removal through the *data plane*, not the
    # stack status: a faked DeleteAcmeEndpoint would leave the endpoint describable.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    deleted[0] = True

    expected_message = f"Could not find ACME endpoint {endpoint_arn}."
    code, message = _error_code(lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after stack deletion, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert endpoint_arn not in _list_acme_endpoint_arns(acm), (
        "stack-deleted endpoint must not appear in ListAcmeEndpoints"
    )
    mutation_code, mutation_message = _error_code(
        lambda: acm.update_acme_endpoint(AcmeEndpointArn=endpoint_arn, Contact="NOT_REQUIRED")
    )
    assert mutation_code == "ResourceNotFoundException", (
        f"UpdateAcmeEndpoint against a stack-deleted ARN should raise ResourceNotFoundException, "
        f"got {mutation_code!r}"
    )
    assert mutation_message == expected_message, f"expected message {expected_message!r}, got {mutation_message!r}"


def _require_acme_api(client) -> None:
    if "CreateAcmeEndpoint" not in client.meta.service_model.operation_names:
        raise AssertionError(
            "installed botocore lacks the ACM ACME endpoint operations "
            "(CreateAcmeEndpoint/DescribeAcmeEndpoint/DeleteAcmeEndpoint) -- upgrade botocore/boto3 "
            "to a version that models the ACM ACME endpoint API surface"
        )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_acme_endpoint_arns(client) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = client.list_acme_endpoints(**kwargs)
        arns.update(e["AcmeEndpointArn"] for e in page.get("AcmeEndpoints", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return arns


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
