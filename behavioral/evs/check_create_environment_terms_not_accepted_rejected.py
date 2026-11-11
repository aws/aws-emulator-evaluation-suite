"""create-environment-terms-not-accepted-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-environment-terms-not-accepted-rejected"
GROUP = "overly-permissive"
SERVICES = ["evs"]

_GATE = "Request validation failure: You must be subscribed to AWS Premium Support"
_TERMS = "Terms and Conditions must be accepted before creating an environment"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Without a Business/Enterprise support plan CreateEnvironment is refused by the Premium Support
    entitlement gate for both termsAccepted values; with termsAccepted=False the " | "-joined
    message also names the unaccepted terms, with termsAccepted=True the gate alone."""
    evs = ctx.client("evs", config=Config(parameter_validation=False))
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, "10.96.0.0/16", "10.96.0.0/24")

    # Positive control: EVS control-plane reads succeed, so the refusal asserted below cannot
    # be explained by broken credentials or a blanket permissions denial.
    evs.get_versions()
    evs.list_environments()

    for terms_accepted in (False, True):
        name = ctx.unique_name(f"sim2real-evs-terms-{str(terms_accepted).lower()}-")
        code, message = _error_detail(
            ctx,
            lambda terms=terms_accepted, name=name: evs.create_environment(
                vpcId=vpc_id,
                serviceAccessSubnetId=subnet_id,
                vcfVersion="SELF_DEPLOYED",
                termsAccepted=terms,
                initialVlans=_initial_vlans("10.96.1" if terms else "10.96.2"),
                environmentName=name,
            ),
        )
        assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
        expected = _GATE if terms_accepted else f"{_GATE} | {_TERMS}"
        assert message == expected, (
            f"termsAccepted={terms_accepted}: expected {expected!r}, got {message!r}"
        )
        assert not any(
            s["environmentName"] == name for s in _list_all_environments(ctx)
        ), f"termsAccepted={terms_accepted} environment {name!r} unexpectedly appears in list_environments"


# ===== helpers =====

def _error_detail(ctx, fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    env_id = result.get("environment", {}).get("environmentId")
    if env_id:
        ctx.on_cleanup(lambda: _safe_delete_environment(ctx, env_id))
    raise AssertionError(
        f"expected CreateEnvironment to be rejected by the Premium Support entitlement gate, "
        f"but it succeeded and returned {result!r}"
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
    # EVS requires the VPC's DHCP option set to carry a domain name, two DNS servers and an
    # NTP server; the default option set (AmazonProvidedDNS, no ntp-servers key) fails
    # CreateEnvironment's own validation before EVS gets to any other check. Created (and its
    # cleanup registered) before the VPC so that LIFO teardown deletes the VPC first — a DHCP
    # option set cannot be deleted while a VPC is still associated with it.
    dhcp_options_id = ec2.create_dhcp_options(
        DhcpConfigurations=[
            {"Key": "domain-name", "Values": ["ec2.internal"]},
            {"Key": "domain-name-servers", "Values": ["10.0.0.2", "10.0.0.3"]},
            {"Key": "ntp-servers", "Values": ["169.254.169.123"]},
        ]
    )["DhcpOptions"]["DhcpOptionsId"]
    ctx.on_cleanup(lambda: ec2.delete_dhcp_options(DhcpOptionsId=dhcp_options_id))

    vpc_id = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.associate_dhcp_options(DhcpOptionsId=dhcp_options_id, VpcId=vpc_id)
    az = _first_az(ctx)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az
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
