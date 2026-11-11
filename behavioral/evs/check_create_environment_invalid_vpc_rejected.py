"""create-environment-invalid-vpc-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-environment-invalid-vpc-rejected"
GROUP = "errors"
SERVICES = ["evs"]

_GATE = "Request validation failure: You must be subscribed to AWS Premium Support"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment against a well-formed but nonexistent vpcId/subnetId is rejected with a
    ValidationException whose " | "-joined message names the VPC as invalid, a clause the same
    request against a real VPC/subnet does not carry, and no environment is created."""
    evs = ctx.client("evs")

    bad_vpc_id = "vpc-00000000"
    rejected_name = ctx.unique_name("sim2real-evs-badvpc-")
    code, message = _error(
        lambda: evs.create_environment(
            vpcId=bad_vpc_id,
            serviceAccessSubnetId="subnet-00000000",
            vcfVersion="SELF_DEPLOYED",
            termsAccepted=True,
            initialVlans=_initial_vlans("10.99.1"),
            environmentName=rejected_name,
            **_self_deployed_unused_fields(),
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a nonexistent vpc/subnet, got {code!r}"
    expected = (
        f"{_GATE} | The VPC id {bad_vpc_id} is not valid or does not exist. "
        f"Please verify the VPC id exists and is valid."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"
    assert not any(
        s["environmentName"] == rejected_name for s in _list_all_environments(ctx)
    ), f"rejected environment {rejected_name!r} unexpectedly appeared in list_environments"

    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, "10.98.0.0/16", "10.98.0.0/24")
    control_name = ctx.unique_name("sim2real-evs-goodvpc-")
    control_code, control_message = _error(
        lambda: evs.create_environment(
            vpcId=vpc_id,
            serviceAccessSubnetId=subnet_id,
            vcfVersion="SELF_DEPLOYED",
            termsAccepted=True,
            initialVlans=_initial_vlans("10.98.1"),
            environmentName=control_name,
            tags={"sim2real-check": CHECK},
            **_self_deployed_unused_fields(),
        )
    )
    assert control_code == "ValidationException", (
        f"positive control: expected ValidationException, got {control_code!r}: {control_message!r}"
    )
    assert control_message == _GATE, (
        f"positive control: a real vpc/subnet must not be named invalid; expected "
        f"{_GATE!r}, got {control_message!r}"
    )
    assert not any(
        s["environmentName"] == control_name for s in _list_all_environments(ctx)
    ), f"refused environment {control_name!r} unexpectedly appeared in list_environments"


# ===== helpers =====

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target ACCEPTING a call real AWS refuses must not be reported as a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _self_deployed_unused_fields() -> dict:
    """licenseInfo/hosts/connectivityInfo/vcfHostnames/siteId: the installed botocore
    model marks these unconditionally required on CreateEnvironmentRequest even though
    the API documents them as not supported for vcfVersion=SELF_DEPLOYED. Shape-valid
    placeholders satisfy botocore's local validation so the request reaches AWS at all;
    the assertions above are on AWS's response, not on these values."""
    return {
        "licenseInfo": [{"solutionKey": "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE", "vsanKey": "FFFFF-GGGGG-HHHHH-IIIII-JJJJJ"}],
        "hosts": [
            {"hostName": f"sim2real-unused-h{i}", "keyName": "sim2real-unused-key", "instanceType": "i4i.metal"}  # large-instance: EVS is metal-only; refused, launches nothing
            for i in range(4)
        ],
        "connectivityInfo": {"privateRouteServerPeerings": ["sim2real-rsp-a", "sim2real-rsp-b"]},
        "vcfHostnames": {
            "vCenter": "sim2real-vc",
            "nsx": "sim2real-nsx",
            "nsxManager1": "sim2real-nsxm1",
            "nsxManager2": "sim2real-nsxm2",
            "nsxManager3": "sim2real-nsxm3",
            "nsxEdge1": "sim2real-nsxe1",
            "nsxEdge2": "sim2real-nsxe2",
            "sddcManager": "sim2real-sddc",
            "cloudBuilder": "sim2real-cb",
        },
        "siteId": "sim2real-unused-site",
    }


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    return azs[0]["ZoneName"]


def _create_evs_compatible_dhcp_options(ctx) -> str:
    """EVS's CreateEnvironment validates the target VPC's DHCP options set: it requires
    explicit 'domain-name', 'domain-name-servers' (two distinct IPv4s -- 'AmazonProvidedDNS'
    is refused despite the error text offering it) and 'ntp-servers' keys, none of which the
    account's default DHCP options set carries. Fixing this isolates the entitlement-gate
    message from unrelated validation noise."""
    ec2 = ctx.client("ec2")
    dhcp_options_id = ec2.create_dhcp_options(
        DhcpConfigurations=[
            {"Key": "domain-name", "Values": ["us-west-2.compute.internal"]},
            {"Key": "domain-name-servers", "Values": ["10.0.0.2", "10.0.0.3"]},
            {"Key": "ntp-servers", "Values": ["169.254.169.123"]},
        ],
        TagSpecifications=[
            {
                "ResourceType": "dhcp-options",
                "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
            }
        ],
    )["DhcpOptions"]["DhcpOptionsId"]
    ctx.on_cleanup(lambda: ec2.delete_dhcp_options(DhcpOptionsId=dhcp_options_id))
    return dhcp_options_id


def _create_vpc_and_subnet(ctx, vpc_cidr: str, subnet_cidr: str):
    ec2 = ctx.client("ec2")
    # Registered for cleanup before the VPC, so LIFO teardown deletes the VPC (which drops
    # the association) before it tries to delete the still-associated DHCP options set.
    dhcp_options_id = _create_evs_compatible_dhcp_options(ctx)
    tag_spec = [
        {
            "ResourceType": "vpc",
            "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
        }
    ]
    vpc_id = ec2.create_vpc(CidrBlock=vpc_cidr, TagSpecifications=tag_spec)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.associate_dhcp_options(DhcpOptionsId=dhcp_options_id, VpcId=vpc_id)
    az = _first_az(ctx)
    subnet_tag_spec = [
        {
            "ResourceType": "subnet",
            "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
        }
    ]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az, TagSpecifications=subnet_tag_spec
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


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


def _list_all_environments(ctx) -> list:
    evs = ctx.client("evs")
    out = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = evs.list_environments(**kwargs)
        out.extend(resp.get("environmentSummaries", []))
        token = resp.get("nextToken")
        if not token:
            return out


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
