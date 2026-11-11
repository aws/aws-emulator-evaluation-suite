"""modify-ip-pools-nonexistent-lb-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-ip-pools-nonexistent-lb-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


_BOGUS_POOL_ID = "ipam-pool-0123456789abcdef0"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyIpPools on a well-formed but non-existent load balancer ARN raises LoadBalancerNotFound.
    The same bogus pool id on a real load balancer must fail differently, proving the not-found
    error is about the ARN rather than ModifyIpPools always rejecting."""
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    real_arn = _create_alb(ctx, elbv2, ec2)
    control_code, _ = _error(
        lambda: elbv2.modify_ip_pools(
            LoadBalancerArn=real_arn,
            IpamPools={"Ipv4IpamPoolId": _BOGUS_POOL_ID},
        )
    )
    assert control_code not in ("LoadBalancerNotFoundException", "LoadBalancerNotFound"), (
        f"expected a pool/validation error against a real load balancer, got {control_code!r}"
    )

    fake_arn = _fake_lb_arn(ctx)
    code, message = _error(
        lambda: elbv2.modify_ip_pools(
            LoadBalancerArn=fake_arn,
            IpamPools={"Ipv4IpamPoolId": _BOGUS_POOL_ID},
        )
    )
    assert code == "LoadBalancerNotFound", (
        f"expected LoadBalancerNotFoundException, got {code!r}"
    )
    expected = f"Load balancer '{fake_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _fake_lb_arn(ctx):
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    rand = ctx.unique_name("nonexistent-lb").replace("sim2real-", "").replace("_", "-")
    return f"arn:aws:elasticloadbalancing:{ctx.region}:{account}:loadbalancer/app/{rand}/0123456789abcdef"


def _two_az_subnets(ctx, ec2) -> list:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]

    # No usable shared network — provision a minimal one of our own rather than
    # depending on an ambient resource a freshly provisioned account may lack.
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    subnet_ids = []
    for i in range(2):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.90.{i}.0/24",
            AvailabilityZone=azs[i % len(azs)]["ZoneName"],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)
    return subnet_ids


def _create_alb(ctx, elbv2, ec2) -> str:
    subnet_ids = _two_az_subnets(ctx, ec2)

    name = ctx.unique_name("sim2real-ippnf-").replace("_", "-")
    if len(name) > 32:
        name = name[-32:]
    name = name.strip("-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    return lb_arn


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
