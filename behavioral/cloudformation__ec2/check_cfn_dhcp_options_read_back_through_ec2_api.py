"""cfn-dhcp-options-read-back-through-ec2-api."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-dhcp-options-read-back-through-ec2-api"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(domain_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "D": {
                    "Type": "AWS::EC2::DHCPOptions",
                    "Properties": {
                        "DomainName": domain_name,
                        "DomainNameServers": ["AmazonProvidedDNS"],
                        "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    },
                }
            },
            "Outputs": {"DId": {"Value": {"Ref": "D"}}},
        }
    )


def _delete_and_wait(cfn, name) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; any other end raises."""
    cfn.delete_stack(StackName=name)
    final = _wait_delete(cfn, name)
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {name} teardown ended {final!r}")


def _wait_create(cfn, name, timeout_s=180.0, interval_s=2.0):
    """Poll DescribeStacks to a terminal create/rollback status.

    A stack CreateStack just accepted can briefly read back as not-found before the control
    plane converges; that is tolerated the same way any other transitional status is, by
    continuing to poll rather than failing on it.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                time.sleep(interval_s)
                continue
            raise
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} never reached a terminal state, last={last!r}")


def _wait_delete(cfn, name, timeout_s=180.0, interval_s=2.0):
    """Poll DescribeStacks until DELETE_COMPLETE.

    Once a delete finishes, DescribeStacks can answer "does not exist" and never report
    DELETE_COMPLETE; botocore's own ``stack_delete_complete`` waiter treats that error as the
    success condition, and this does the same.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return "DELETE_COMPLETE"
            raise
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} never reached a terminal state, last={last!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack's AWS::EC2::DHCPOptions is independently readable at EC2 by its own
    PhysicalResourceId, not just reported by CloudFormation, and deleting the stack removes
    it from EC2 too."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-behav-cfn-dhcp-stack-")
    domain_name = f"{ctx.unique_name('sim2real-behav-cfn-dhcp-domain-')}.internal"

    cfn.create_stack(StackName=stack_name, TemplateBody=_template(domain_name))
    ctx.on_cleanup(lambda: _delete_and_wait(cfn, stack_name))

    status = _wait_create(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    assert len(resources) == 1, f"expected exactly one stack resource, got {resources!r}"
    physical_id = resources[0]["PhysicalResourceId"]

    described = ec2.describe_dhcp_options(DhcpOptionsIds=[physical_id])["DhcpOptions"]
    assert len(described) == 1, f"expected exactly one DHCP options set, found {described!r}"
    configs = {c["Key"]: [v["Value"] for v in c["Values"]] for c in described[0]["DhcpConfigurations"]}
    assert configs.get("domain-name") == [domain_name], (
        f"expected domain-name {[domain_name]!r}, got {configs.get('domain-name')!r}"
    )
    assert configs.get("domain-name-servers") == ["AmazonProvidedDNS"], (
        f"expected domain-name-servers ['AmazonProvidedDNS'], got {configs.get('domain-name-servers')!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    final_status = _wait_delete(cfn, stack_name)
    assert final_status == "DELETE_COMPLETE", f"expected DELETE_COMPLETE, got {final_status!r}"

    code, message = _not_found(lambda: ec2.describe_dhcp_options(DhcpOptionsIds=[physical_id]))
    assert code == "InvalidDhcpOptionID.NotFound", (
        f"deleting the stack must remove the DHCP options set from EC2, got {code!r}: {message!r}"
    )
    expected_message = f"The dhcpOption ID '{physical_id}' does not exist"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _not_found(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the DHCP options set to be gone, but it was found: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
