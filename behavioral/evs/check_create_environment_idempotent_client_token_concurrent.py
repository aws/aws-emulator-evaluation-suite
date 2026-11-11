"""create-environment-idempotent-client-token-concurrent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-environment-idempotent-client-token-concurrent"
GROUP = "concurrency"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateEnvironment calls sharing one clientToken are refused IDENTICALLY (same
    code and message, the AWS Premium Support entitlement gate on an account without it), and no
    environment ever appears; GetVersions proves the EVS API is reachable."""
    evs = ctx.client("evs")

    versions = evs.get_versions()["vcfVersions"]
    assert versions, f"GetVersions returned no vcfVersions; evs API is unreachable: {versions!r}"

    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, "10.93.0.0/16", "10.93.0.0/24")
    env_name = ctx.unique_name("sim2real-evs-")
    client_token = ctx.unique_name("sim2real-evs-token-")

    def _create():
        try:
            env = evs.create_environment(
                vpcId=vpc_id,
                serviceAccessSubnetId=subnet_id,
                vcfVersion="SELF_DEPLOYED",
                termsAccepted=True,
                initialVlans=_initial_vlans("10.93.1"),
                environmentName=env_name,
                clientToken=client_token,
            )["environment"]
            return (env["environmentId"], None)
        except Exception as exc:
            return (None, _error_code_and_message(exc))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_create)
        fut_b = pool.submit(_create)
        env_id_a, result_a = fut_a.result()
        env_id_b, result_b = fut_b.result()

    for env_id in (env_id_a, env_id_b):
        if env_id is not None:
            ctx.on_cleanup(lambda eid=env_id: _safe_delete_environment(ctx, eid))

    assert env_id_a is None, (
        f"concurrent CreateEnvironment (leg a) unexpectedly succeeded ({env_id_a!r}); "
        "the account now has AWS Premium Support or EVS no longer enforces it"
    )
    assert env_id_b is None, (
        f"concurrent CreateEnvironment (leg b) unexpectedly succeeded ({env_id_b!r}); "
        "the account now has AWS Premium Support or EVS no longer enforces it"
    )

    code_a, message_a = result_a
    code_b, message_b = result_b
    assert code_a == "ValidationException", f"expected ValidationException, got {code_a!r}: {message_a!r}"
    assert "You must be subscribed to AWS Premium Support" in message_a, (
        f"expected the Premium Support entitlement gate, got: {message_a!r}"
    )
    assert (code_a, message_a) == (code_b, message_b), (
        "two concurrent CreateEnvironment calls sharing one clientToken were refused "
        f"differently: {(code_a, message_a)!r} vs {(code_b, message_b)!r}"
    )

    matches = [s for s in _list_all_environments(ctx) if s["environmentName"] == env_name]
    assert not matches, f"an environment named {env_name!r} exists despite CreateEnvironment being refused: {matches!r}"


# ===== helpers =====

def _error_code_and_message(exc: Exception) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    if not isinstance(exc, ClientError):
        raise exc
    err = exc.response["Error"]
    return err["Code"], err["Message"]


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
    name = ctx.unique_name("sim2real-evs-")
    vpc_id = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    # EVS validates the VPC's DHCP options set before it will provision an environment: it
    # requires 'domain-name', 'ntp-servers' and two distinct IPv4 'domain-name-servers' —
    # none of which the account default DHCP options set (AmazonProvidedDNS, no ntp-servers)
    # satisfies.
    # Not a region pin: this follows ctx.region wherever the check runs, and only encodes
    # AWS's own domain-name-suffix naming convention (us-east-1 is the one exception).
    domain_name = "ec2.internal" if ctx.region == "us-east-1" else f"{ctx.region}.compute.internal"
    dhcp_options_id = ec2.create_dhcp_options(
        DhcpConfigurations=[
            {"Key": "domain-name", "Values": [domain_name]},
            {"Key": "domain-name-servers", "Values": ["10.0.0.2", "10.0.0.3"]},
            {"Key": "ntp-servers", "Values": ["169.254.169.123"]},
        ],
        TagSpecifications=[{"ResourceType": "dhcp-options", "Tags": [{"Key": "Name", "Value": name}]}],
    )["DhcpOptions"]["DhcpOptionsId"]
    ctx.on_cleanup(lambda: ec2.delete_dhcp_options(DhcpOptionsId=dhcp_options_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.associate_dhcp_options(VpcId=vpc_id, DhcpOptionsId=dhcp_options_id)
    az = _first_az(ctx)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _safe_delete_environment(ctx, env_id: str) -> None:
    evs = ctx.client("evs")
    try:
        evs.delete_environment(environmentId=env_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
