"""deploy-ec2-interface-vpc-endpoint-dns-entries-match-getatt-and-delete."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-interface-vpc-endpoint-dns-entries-match-getatt-and-delete"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

VPC_BLOCK = "10.87.0.0/16"
SUBNET_BLOCK = "10.87.0.0/24"
_DELIM = ";"


def _template(service_name: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Az": {"Type": "String"},
        },
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": SUBNET_BLOCK,
                    "AvailabilityZone": {"Ref": "Az"},
                },
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real-xsvc-vpcednsentr",
                    "VpcId": {"Ref": "Vpc"},
                },
            },
            "Endpoint": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "ServiceName": service_name,
                    "VpcEndpointType": "Interface",
                    "SubnetIds": [{"Ref": "Subnet"}],
                    "SecurityGroupIds": [{"Fn::GetAtt": ["Sg", "GroupId"]}],
                    "PrivateDnsEnabled": False,
                },
            },
        },
        "Outputs": {
            "EndpointId": {"Value": {"Ref": "Endpoint"}},
            "DnsEntries": {
                "Value": {"Fn::Join": [_DELIM, {"Fn::GetAtt": ["Endpoint", "DnsEntries"]}]}
            },
        },
    }


_CREATE_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _stack(cfn, stack_id: str) -> dict:
    """The stack read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return {"StackId": stack_id, "StackStatus": "DELETE_COMPLETE"}
        raise


def _wait_stack(ctx, cfn, stack_id: str, terminal, timeout_s: float) -> dict:
    return _poll_until(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: s["StackStatus"] in terminal,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"stack {stack_id} reaches one of {sorted(terminal)}",
    )


def _delete_stack(ctx, cfn, stack_id: str, timeout_s: float = 900.0) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(ctx, cfn, stack_id, _DELETE_TERMINAL, timeout_s)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _usable_az(ec2, service_name: str) -> str:
    offered = set(
        ec2.describe_vpc_endpoint_services(
            Filters=[{"Name": "service-name", "Values": [service_name]}]
        )["ServiceDetails"][0]["AvailabilityZones"]
    )
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no available AZ offers {service_name!r}; offered zones were {sorted(offered)!r}"
    )
    return usable[0]


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN interface AWS::EC2::VPCEndpoint's Fn::GetAtt DnsEntries equals DescribeVpcEndpoints'
    exact pair set: a regional and a zonal vpce name for the endpoint id under one hosted zone;
    deleting the stack deletes the endpoint."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    service_name = f"com.amazonaws.{ctx.region}.ssm"
    az = _usable_az(ec2, service_name)

    name = ctx.unique_name("sim2real-xsvc-vpcednsentr-")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(_template(service_name)),
        Parameters=[{"ParameterKey": "Az", "ParameterValue": az}],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))

    stack = _wait_stack(ctx, cfn, stack_id, _CREATE_TERMINAL, 600.0)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    endpoint_id = outputs["EndpointId"]

    getatt_entries = set()
    for entry in outputs["DnsEntries"].split(_DELIM):
        zone_id, dns_name = entry.split(":", 1)
        getatt_entries.add((zone_id, dns_name))

    ep = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    ec2_entries = {(e["HostedZoneId"], e["DnsName"]) for e in ep["DnsEntries"]}
    assert getatt_entries == ec2_entries, (
        f"Fn::GetAtt DnsEntries {getatt_entries!r} disagrees with EC2's own "
        f"DescribeVpcEndpoints DnsEntries {ec2_entries!r}"
    )

    # The regional name is <endpoint id>-<generated suffix>.<service>.<region>.vpce.amazonaws.com;
    # the zonal one inserts -<az> after the suffix. Only the suffix is generated.
    domain = f"ssm.{ctx.region}.vpce.amazonaws.com"
    regional = re.compile(re.escape(endpoint_id) + r"-([a-z0-9]{8})\." + re.escape(domain))
    matches = [m for _, n in ec2_entries if (m := regional.fullmatch(n))]
    assert len(matches) == 1, f"expected exactly one regional vpce name, got {ec2_entries!r}"
    suffix = matches[0].group(1)
    zones = {z for z, _ in ec2_entries}
    assert len(zones) == 1, f"expected one shared HostedZoneId, got {ec2_entries!r}"
    zone = zones.pop()
    want = {
        (zone, f"{endpoint_id}-{suffix}.{domain}"),
        (zone, f"{endpoint_id}-{suffix}-{az}.{domain}"),
    }
    assert ec2_entries == want, f"DnsEntries {ec2_entries!r}, expected {want!r}"

    _delete_stack(ctx, cfn, stack_id)
    endpoint_gone = (
        "InvalidVpcEndpointId.NotFound",
        f"The Vpc Endpoint Id '{endpoint_id}' does not exist",
    )
    _expect_error(lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id]), *endpoint_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
