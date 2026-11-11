"""op-contract-describe-load-balancers."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-load-balancers"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLoadBalancers filters correctly by Name/ARN; an unknown name is rejected as not-found."""
    _, subnet_ids = _default_vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:

        raise AssertionError(f"need >=2 subnets in distinct AZs to create an ALB, found {len(subnet_ids)}")

    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, subnet_ids)

    by_name = elbv2.describe_load_balancers(Names=[lb["LoadBalancerName"]])["LoadBalancers"]
    assert len(by_name) == 1, f"expected exactly 1 match by name, got {by_name!r}"
    assert by_name[0]["LoadBalancerArn"] == lb["LoadBalancerArn"], (
        f"expected ARN {lb['LoadBalancerArn']}, got {by_name[0]['LoadBalancerArn']}"
    )
    assert by_name[0]["Type"] == "application", f"expected Type application, got {by_name[0]['Type']}"
    assert by_name[0]["Scheme"] == "internet-facing", f"expected Scheme internet-facing, got {by_name[0]['Scheme']}"
    assert by_name[0]["IpAddressType"] == lb["IpAddressType"], (
        f"expected IpAddressType {lb['IpAddressType']}, got {by_name[0]['IpAddressType']}"
    )

    by_arn = elbv2.describe_load_balancers(LoadBalancerArns=[lb["LoadBalancerArn"]])["LoadBalancers"]
    assert len(by_arn) == 1 and by_arn[0]["LoadBalancerName"] == lb["LoadBalancerName"], (
        f"expected exactly 1 match named {lb['LoadBalancerName']}, got {by_arn!r}"
    )

    missing_name = ctx.unique_name("sim2real-alb-miss-")
    code, message = _error(lambda: elbv2.describe_load_balancers(Names=[missing_name]))
    # ELBv2 returns the error code without the model's "Exception" suffix. The name prefix stays
    # short: a name over the 32-char limit raises ValidationError instead of not-found.
    assert code == "LoadBalancerNotFound", f"expected not-found, got {code}"
    expected = f"Load balancers '[{missing_name}]' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) >= 2:
        return vpc_id, list(by_az.values())

    # No usable shared network (a freshly provisioned account may not have one) -- create the
    # minimal network this check needs rather than depending on ambient account state.
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=_managed_tags())
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az["ZoneName"]
        )["Subnet"]
        sid = subnet["SubnetId"]
        ec2.create_tags(Resources=[sid], Tags=_managed_tags())
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)
    return vpc_id, subnet_ids


def _managed_tags():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-alb"}]


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-alb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids[:2], Type="application", Tags=_managed_tags())
    lb = resp["LoadBalancers"][0]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb["LoadBalancerArn"]))
    return lb


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry inside one shared window, then fail naming the ENIs left.
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
