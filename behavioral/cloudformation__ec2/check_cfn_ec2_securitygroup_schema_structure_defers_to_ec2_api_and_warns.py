"""cfn-ec2-securitygroup-schema-structure-defers-to-ec2-api-and-warns."""
from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-securitygroup-schema-structure-defers-to-ec2-api-and-warns"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

# CloudFormation's resource-handler wrapping of an EC2 service error; the request id and token vary.
_REASON_EC2API = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)
# The same wrapping around a handler-level message with no embedded service/status suffix.
_REASON_PLAIN = re.compile(
    r'^Resource handler returned message: "(?P<message>[^"]*)" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)

_WARN_EXTRANEOUS = (
    "Resource template validation failed for resource SG as the template has invalid properties. "
    "Please refer to the resource documentation to fix the template.\n"
    "Properties validation failed for resource SG with message:\n"
    "#: extraneous key [Bogus] is not permitted"
)
_WARN_MISSING_IPPROTOCOL = (
    "Resource template validation failed for resource SG as the template has invalid properties. "
    "Please refer to the resource documentation to fix the template.\n"
    "Properties validation failed for resource SG with message:\n"
    "#/SecurityGroupEgress/0: required key [IpProtocol] not found"
)


def _template(vpc_id: str, props: dict) -> str:
    full = dict(props)
    full["VpcId"] = vpc_id
    return json.dumps({"Resources": {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": full}}})


def _wait_terminal(cfn, name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _sg_events(cfn, name: str) -> list[tuple]:
    """``(status, reason)`` for every SG event, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=name)
    events = [e for page in pages for e in page["StackEvents"]]
    return [(e.get("ResourceStatus"), e.get("ResourceStatusReason"))
            for e in reversed(events) if e.get("LogicalResourceId") == "SG"]


def _delete_stack(cfn, name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AWS::EC2::SecurityGroup refuses a missing required property or a deprecated one in its
    resource handler with an exact message, not at pre-provisioning property validation, and warns
    on but accepts an unsupported property or a wrong-typed scalar.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/24", TagSpecifications=[{
            "ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    # Every stack is created up front and waited on together; each is a separate case.
    cases = {
        # Positive control: GroupDescription present, Egress.IpProtocol present.
        "ok": {
            "GroupDescription": "control security group",
            "SecurityGroupEgress": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.0.0.0/32"}],
        },
        "nodesc": {},
        "noproto": {
            "GroupDescription": "missing egress protocol",
            "SecurityGroupEgress": [{"CidrIp": "10.0.0.0/32"}],
        },
        "bogus": {"GroupDescription": "has an unsupported property", "Bogus": "x"},
        "type": {"GroupDescription": 12345},
        "dep": {
            "GroupDescription": "uses a deprecated egress property",
            "SecurityGroupEgress": [{
                "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                "SourceSecurityGroupId": "sg-00000000000000000",
            }],
        },
    }
    stacks: dict[str, str] = {}
    for case, props in cases.items():
        stack = ctx.unique_name(f"sim2real-behav-sgschema-{case}-")
        cfn.create_stack(StackName=stack, TemplateBody=_template(vpc_id, props))
        ctx.on_cleanup(lambda stack=stack: _delete_stack(cfn, stack))
        stacks[case] = stack
    with ThreadPoolExecutor(max_workers=len(stacks)) as pool:
        statuses = dict(zip(stacks, pool.map(lambda name: _wait_terminal(cfn, name), stacks.values())))

    status = statuses["ok"]
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    good_physical = cfn.describe_stack_resources(StackName=stacks["ok"], LogicalResourceId="SG")[
        "StackResources"][0]["PhysicalResourceId"]
    good_sg = ec2.describe_security_groups(GroupIds=[good_physical])["SecurityGroups"][0]
    assert good_sg["Description"] == "control security group", (
        f"control SG description read back as {good_sg['Description']!r}"
    )

    # Case: missing the required top-level GroupDescription is refused at the EC2 API, not by
    # pre-provisioning schema validation.
    status = statuses["nodesc"]
    assert status == "ROLLBACK_COMPLETE", f"missing GroupDescription: expected ROLLBACK_COMPLETE, got {status!r}"
    failed = [r for s, r in _sg_events(cfn, stacks["nodesc"]) if s == "CREATE_FAILED"]
    assert len(failed) == 1, f"missing GroupDescription: expected one CREATE_FAILED event, got {failed!r}"
    match = _REASON_EC2API.match(failed[0])
    assert match is not None, f"missing GroupDescription: reason is not an EC2-wrapped message: {failed[0]!r}"
    got = (match["message"], match["service"], match["status"], match["handler"])
    want = ("The request must contain the parameter GroupDescription", "Ec2", "400", "InvalidRequest")
    assert got == want, f"missing GroupDescription: expected {want!r}, got {got!r}"
    resources = cfn.list_stack_resources(StackName=stacks["nodesc"])["StackResourceSummaries"]
    resource_statuses = [r["ResourceStatus"] for r in resources]
    assert resource_statuses == ["DELETE_COMPLETE"], (
        f"missing GroupDescription: a never-created resource must roll back to DELETE_COMPLETE, "
        f"got {resource_statuses!r}"
    )

    # Case: Egress.IpProtocol missing is WARNED by schema validation but not blocked there; the
    # creation then fails at the EC2 API itself.
    status = statuses["noproto"]
    assert status == "ROLLBACK_COMPLETE", f"missing Egress.IpProtocol: expected ROLLBACK_COMPLETE, got {status!r}"
    events_b = _sg_events(cfn, stacks["noproto"])
    warn_reasons = {r for s, r in events_b if s == "CREATE_IN_PROGRESS" and r}
    assert _WARN_MISSING_IPPROTOCOL in warn_reasons, (
        f"missing Egress.IpProtocol: expected the WARN reason among {warn_reasons!r}"
    )
    failed_b = [r for s, r in events_b if s == "CREATE_FAILED"]
    assert len(failed_b) == 1, f"missing Egress.IpProtocol: expected one CREATE_FAILED event, got {failed_b!r}"
    match_b = _REASON_EC2API.match(failed_b[0])
    assert match_b is not None, f"missing Egress.IpProtocol: reason is not an EC2-wrapped message: {failed_b[0]!r}"
    got_b = (match_b["message"], match_b["service"], match_b["status"], match_b["handler"])
    want_b = (
        "Invalid value 'null' for protocol. VPC security group rules must specify protocols explicitly.",
        "Ec2", "400", "InvalidRequest",
    )
    assert got_b == want_b, f"missing Egress.IpProtocol: expected {want_b!r}, got {got_b!r}"

    # Case: an unsupported property is WARNED but the create still succeeds, ignoring it.
    status = statuses["bogus"]
    assert status == "CREATE_COMPLETE", f"unsupported property: expected CREATE_COMPLETE, got {status!r}"
    events_bogus = _sg_events(cfn, stacks["bogus"])
    warn_bogus = {r for s, r in events_bogus if s == "CREATE_IN_PROGRESS" and r}
    assert _WARN_EXTRANEOUS in warn_bogus, f"unsupported property: expected the WARN reason among {warn_bogus!r}"
    bogus_physical = cfn.describe_stack_resources(StackName=stacks["bogus"], LogicalResourceId="SG")[
        "StackResources"][0]["PhysicalResourceId"]
    bogus_sg = ec2.describe_security_groups(GroupIds=[bogus_physical])["SecurityGroups"][0]
    assert bogus_sg["Description"] == "has an unsupported property", (
        f"unsupported property: created SG description read back as {bogus_sg['Description']!r}"
    )

    # Case: a wrong-typed scalar (a JSON number for a string property) is silently coerced, with
    # no validation warning at all.
    status = statuses["type"]
    assert status == "CREATE_COMPLETE", f"wrong-typed GroupDescription: expected CREATE_COMPLETE, got {status!r}"
    events_type = _sg_events(cfn, stacks["type"])
    warn_type = {r for s, r in events_type if s == "CREATE_IN_PROGRESS" and r and "validation failed" in r}
    assert warn_type == set(), f"wrong-typed GroupDescription: expected no validation WARN, got {warn_type!r}"
    type_physical = cfn.describe_stack_resources(StackName=stacks["type"], LogicalResourceId="SG")[
        "StackResources"][0]["PhysicalResourceId"]
    type_sg = ec2.describe_security_groups(GroupIds=[type_physical])["SecurityGroups"][0]
    assert type_sg["Description"] == "12345", (
        f"wrong-typed GroupDescription: coerced description read back as {type_sg['Description']!r}"
    )

    # Case: the deprecated SecurityGroupEgress.SourceSecurityGroupId is refused outright.
    status = statuses["dep"]
    assert status == "ROLLBACK_COMPLETE", f"deprecated SourceSecurityGroupId: expected ROLLBACK_COMPLETE, got {status!r}"
    failed_dep = [r for s, r in _sg_events(cfn, stacks["dep"]) if s == "CREATE_FAILED"]
    assert len(failed_dep) == 1, f"deprecated SourceSecurityGroupId: expected one CREATE_FAILED event, got {failed_dep!r}"
    match_dep = _REASON_PLAIN.match(failed_dep[0])
    assert match_dep is not None, f"deprecated SourceSecurityGroupId: reason is not an EC2-wrapped message: {failed_dep[0]!r}"
    got_dep = (match_dep["message"], match_dep["handler"])
    want_dep = (
        "The SourceSecurityGroupId property has been deprecated for "
        "AWS::EC2::SecurityGroup.SecurityGroupEgress. Please use DestinationSecurityGroupId instead",
        "InvalidRequest",
    )
    assert got_dep == want_dep, f"deprecated SourceSecurityGroupId: expected {want_dep!r}, got {got_dep!r}"

    # Control survives all the rejections above.
    still = ec2.describe_security_groups(GroupIds=[good_physical])["SecurityGroups"][0]
    assert still["Description"] == "control security group", (
        f"control SG changed to {still['Description']!r} after the rejections"
    )

    with ThreadPoolExecutor(max_workers=len(stacks)) as pool:
        list(pool.map(lambda name: _delete_stack(cfn, name), stacks.values()))
    got_desc = _describe_error(ec2, good_physical)
    want_desc = ("InvalidGroup.NotFound", f"The security group '{good_physical}' does not exist")
    assert got_desc == want_desc, (
        f"control SG after its stack delete: expected {want_desc!r}, got {got_desc!r}"
    )


def _describe_error(ec2, group_id: str):
    """(Error.Code, Error.Message) of DescribeSecurityGroups(GroupIds=[group_id]); an unexpected
    success fails."""
    try:
        result = ec2.describe_security_groups(GroupIds=[group_id])
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected {group_id} to be gone, but it still describes as {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
