"""describe-load-balancer-nonexistent-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-load-balancer-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeLoadBalancers with a well-formed but nonexistent ARN or name fails with
    LoadBalancerNotFound and its exact message, after a positive control resolves a real
    load balancer by ARN and by name."""
    elbv2 = ctx.client("elbv2")
    region = ctx.region
    # A cross-account ARN fails request validation with a different code, so use the caller's account.
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    real_lb = _create_load_balancer(ctx, elbv2)
    real_arn = real_lb["LoadBalancerArn"]
    real_name = real_lb["LoadBalancerName"]

    # Positive control: a target that always answers LoadBalancerNotFound must not pass.
    by_arn = elbv2.describe_load_balancers(LoadBalancerArns=[real_arn])["LoadBalancers"]
    assert len(by_arn) == 1 and by_arn[0]["LoadBalancerArn"] == real_arn, (
        f"expected the just-created load balancer to resolve by ARN, got {by_arn!r}"
    )
    by_name = elbv2.describe_load_balancers(Names=[real_name])["LoadBalancers"]
    assert len(by_name) == 1 and by_name[0]["LoadBalancerArn"] == real_arn, (
        f"expected the just-created load balancer to resolve by name, got {by_name!r}"
    )

    bogus_arn = (
        f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/app/"
        "sim2real-does-not-exist/0123456789abcdef"
    )

    code, message = _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[bogus_arn]))
    assert code == "LoadBalancerNotFound", f"expected LoadBalancerNotFound, got {code!r}"
    assert message == "One or more load balancers not found", f"MESSAGE={message!r}"

    # Names over the 32-char limit return an empty success instead of LoadBalancerNotFound,
    # so the generated name stays within it.
    missing_name = ctx.unique_name("sim2real-lb-missing-")
    code_by_name, message_by_name = _error(
        lambda: elbv2.describe_load_balancers(Names=[missing_name])
    )
    assert code_by_name == "LoadBalancerNotFound", f"expected LoadBalancerNotFound by name, got {code_by_name!r}"
    assert message_by_name == f"Load balancers '[{missing_name}]' not found", f"MESSAGE={message_by_name!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _setup_network(ctx, ec2, num_subnets=2):
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        per_az = {}
        for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
            per_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
        subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
        if len(subnet_ids) >= min(num_subnets, 2):
            return vpc_id, subnet_ids

    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}])
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return vpc_id, subnet_ids


def _create_load_balancer(ctx, elbv2):
    ec2 = ctx.client("ec2")
    _, subnet_ids = _setup_network(ctx, ec2)
    name = ctx.unique_name("sim2real-lb-real-")[:32].rstrip("-")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Type="application",
        Scheme="internal",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn))
    return lb


# A load balancer, endpoint, cluster, function or instance deletes asynchronously: its ENIs stay
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc
# fails with DependencyViolation. Wait (bounded) for the ENIs to go and retry inside that window.
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
