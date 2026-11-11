"""delete-environment-with-active-connector-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-environment-with-active-connector-rejected"
GROUP = "overly-permissive"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment on an otherwise well-formed request is refused with the "You must be
    subscribed to AWS Premium Support" ValidationException on an account without that plan, while
    ListEnvironments succeeds and no environment by that name appears afterward."""
    evs = ctx.client("evs")

    control = evs.list_environments()
    assert "environmentSummaries" in control, (
        f"expected ListEnvironments to succeed on a healthy account/credential pair, "
        f"got {control!r}"
    )

    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, "10.94.0.0/16", "10.94.0.0/24")
    env_name = ctx.unique_name("sim2real-evs-")

    code, message = _error_code_and_message(
        lambda: evs.create_environment(
            vpcId=vpc_id,
            serviceAccessSubnetId=subnet_id,
            vcfVersion="SELF_DEPLOYED",
            termsAccepted=True,
            initialVlans=_initial_vlans("10.94.1"),
            environmentName=env_name,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    assert message == "Request validation failure: You must be subscribed to AWS Premium Support", (
        f"expected exactly the entitlement-gate message, got: {message!r}"
    )

    after = evs.list_environments()["environmentSummaries"]
    assert not any(e.get("environmentName") == env_name for e in after), (
        f"expected no environment named {env_name!r} to exist after the rejected "
        f"CreateEnvironment, got {after!r}"
    )


# ===== helpers =====

def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _initial_vlans(base: str) -> dict:
    return {
        "edgeVTep": {"cidr": f"{base}.0/28"},
        "expansionVlan1": {"cidr": f"{base}.16/28"},
        "expansionVlan2": {"cidr": f"{base}.32/28"},
        "hcx": {"cidr": f"{base}.48/28"},
        "nsxUplink": {"cidr": f"{base}.64/28"},
        "vmkManagement": {"cidr": f"{base}.80/28"},
        "vmManagement": {"cidr": f"{base}.96/28"},
        "vMotion": {"cidr": f"{base}.112/28"},
        "vSan": {"cidr": f"{base}.128/28"},
        "vTep": {"cidr": f"{base}.144/28"},
    }


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    return azs[0]["ZoneName"]


def _create_vpc_and_subnet(ctx, vpc_cidr: str, subnet_cidr: str):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    # EVS validates the VPC's DHCP options set and rejects the account/VPC default set, which
    # carries no 'ntp-servers' key and (per real-AWS validation observed here) rejects the
    # 'AmazonProvidedDNS' sentinel for domain-name-servers too — it wants two literal IPv4
    # addresses. 169.254.169.123 is the Amazon Time Sync Service address, valid in any VPC. This
    # keeps the CreateEnvironment request below well-formed except for the entitlement gate.
    dhcp_id = ec2.create_dhcp_options(
        DhcpConfigurations=[
            {"Key": "domain-name", "Values": [f"{ctx.region}.compute.internal"]},
            {"Key": "domain-name-servers", "Values": ["10.0.0.2", "10.0.0.3"]},
            {"Key": "ntp-servers", "Values": ["169.254.169.123"]},
        ]
    )["DhcpOptions"]["DhcpOptionsId"]

    def _detach_and_delete_dhcp_options():
        ec2.associate_dhcp_options(DhcpOptionsId="default", VpcId=vpc_id)
        ec2.delete_dhcp_options(DhcpOptionsId=dhcp_id)

    ctx.on_cleanup(_detach_and_delete_dhcp_options)
    ec2.associate_dhcp_options(DhcpOptionsId=dhcp_id, VpcId=vpc_id)

    az = _first_az(ctx)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
