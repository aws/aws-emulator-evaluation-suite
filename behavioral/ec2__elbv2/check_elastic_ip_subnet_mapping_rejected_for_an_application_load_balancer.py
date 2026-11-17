"""elastic-ip-subnet-mapping-rejected-for-an-application-load-balancer."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elastic-ip-subnet-mapping-rejected-for-an-application-load-balancer"
GROUP = "nlb-elastic-ip"
SERVICES = ["ec2", "elbv2"]

#: An internet-facing load balancer leaves `provisioning` well inside this window.
_LB_DEADLINE_S = 600

#: Dependents (the load balancer's ENIs, the EIP associations) release before they can be deleted.
_TEARDOWN_DEADLINE_S = 480


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A subnet mapping's Elastic IP allocation is rejected for an Application Load Balancer and
    accepted for a Network Load Balancer, which then reports that exact address per zone.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancer-subnets.html
    """
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")
    tok = ctx.unique_name("sim2real-nlbeip-")
    net = _network(ctx, tok)
    sg = _no_ingress_sg(ctx, tok, net["vpc"])
    eips = [_allocate_eip(ctx, tok) for _ in net["subnets"]]
    mappings = [{"SubnetId": sn, "AllocationId": a} for sn, a in zip(net["subnets"], eips)]

    alb_name = tok + "-a"
    ctx.on_cleanup(lambda: _delete_lb_named(ctx, alb_name))  # net before the refused attempt
    code, msg = _create_lb_error(elb, Name=alb_name, Type="application", Scheme="internet-facing",
                                 SubnetMappings=mappings, SecurityGroups=[sg])
    assert code == "InvalidConfigurationRequest", f"ALB with Elastic IP mappings: {code!r} ({msg!r})"
    assert msg == "Elastic IPs are not supported for load balancers with type 'application'", (
        f"ALB with Elastic IP mappings message: {msg!r}")
    assert _lb_arns(elb, alb_name) == [], "the refused ALB create left a load balancer behind"

    nlb = elb.create_load_balancer(Name=tok + "-n", Type="network", Scheme="internet-facing",
                                   SubnetMappings=mappings,
                                   Tags=[{"Key": "sim2real", "Value": "nlbeip"}])["LoadBalancers"][0][
        "LoadBalancerArn"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: elb.delete_load_balancer(LoadBalancerArn=nlb),
                                           f"load balancer {nlb}", codes=()))
    _wait_active(elb, nlb)

    d = elb.describe_load_balancers(LoadBalancerArns=[nlb])["LoadBalancers"][0]
    got_allocs = sorted(z["LoadBalancerAddresses"][0]["AllocationId"] for z in d["AvailabilityZones"])
    assert got_allocs == sorted(eips), (
        f"the NLB's zones report allocations {got_allocs!r}, expected the created EIPs {sorted(eips)!r}")
    got_zones = sorted(z["ZoneName"] for z in d["AvailabilityZones"])
    assert got_zones == sorted(net["azs"]), (
        f"the NLB's zones are {got_zones!r}, expected {sorted(net['azs'])!r}")


def _create_lb_error(elb, **kw) -> tuple[str, str]:
    """``(code, message)`` from a refused CreateLoadBalancer; raises if it unexpectedly succeeds."""
    try:
        out = elb.create_load_balancer(**kw)["LoadBalancers"][0]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the create to be refused, but it succeeded: {out!r}")


def _lb_arns(elb, name: str) -> list[str]:
    try:
        return [lb["LoadBalancerArn"] for lb in elb.describe_load_balancers(Names=[name])["LoadBalancers"]]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
            return []
        raise


def _delete_lb_named(ctx, name: str) -> None:
    elb = ctx.client("elbv2")
    for arn in _lb_arns(elb, name):
        _retry_teardown(lambda a=arn: elb.delete_load_balancer(LoadBalancerArn=a),
                        f"load balancer {arn}", codes=())


def _wait_active(elb, arn: str) -> None:
    deadline = time.monotonic() + _LB_DEADLINE_S
    while True:
        state = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            return
        assert state == "provisioning", f"load balancer {arn} left provisioning as {state!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {arn} still {state!r} after {_LB_DEADLINE_S}s")
        time.sleep(5)


def _retry_teardown(fn, what: str, *, codes=("DependencyViolation",)) -> None:
    """Delete, retrying only while a dependent (an ENI still releasing) blocks it."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if "NotFound" in code:
                return
            if code not in codes or time.monotonic() >= deadline:
                raise AssertionError(f"{what}: {code}: {exc}") from exc
        time.sleep(5)


def _tagspec(kind: str, name: str) -> list[dict]:
    return [{"ResourceType": kind,
             "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "nlbeip"}]}]


def _usable_azs(ctx, count: int) -> list[str]:
    """``count`` distinct available AZs; no instances are launched, so no type offering applies."""
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(zones) >= count, f"only {len(zones)} available AZ(s), need {count}: {zones!r}"
    return zones[:count]


def _network(ctx, tok: str) -> dict:
    """A VPC with two subnets in two AZs, with an internet gateway attached so an internet-facing
    load balancer is accepted."""
    ec2 = ctx.client("ec2")
    azs = _usable_azs(ctx, 2)
    vpc = ec2.create_vpc(CidrBlock="172.31.0.0/16",
                         TagSpecifications=_tagspec("vpc", tok))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ec2.delete_vpc(VpcId=vpc), f"vpc {vpc}"))
    igw = ec2.create_internet_gateway(
        TagSpecifications=_tagspec("internet-gateway", tok))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw),
                                           f"igw {igw}"))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_teardown(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc), f"igw {igw} detach"))
    subnets = []
    for i, az in enumerate(azs):
        sn = ec2.create_subnet(VpcId=vpc, CidrBlock=f"172.31.{i}.0/24", AvailabilityZone=az,
                               TagSpecifications=_tagspec("subnet", tok))["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sn=sn: _retry_teardown(lambda: ec2.delete_subnet(SubnetId=sn),
                                                     f"subnet {sn}"))
        subnets.append(sn)
    return {"vpc": vpc, "subnets": subnets, "azs": azs}


def _no_ingress_sg(ctx, tok: str, vpc: str) -> str:
    ec2 = ctx.client("ec2")
    sg = ec2.create_security_group(GroupName=tok, Description=tok, VpcId=vpc,
                                   TagSpecifications=_tagspec("security-group", tok))["GroupId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ec2.delete_security_group(GroupId=sg), f"sg {sg}"))
    return sg


def _allocate_eip(ctx, tok: str) -> str:
    ec2 = ctx.client("ec2")
    alloc = ec2.allocate_address(Domain="vpc",
                                 TagSpecifications=_tagspec("elastic-ip", tok))["AllocationId"]
    # The NLB's deleted ENI releases the address asynchronously; until then, release raises
    # AuthFailure rather than a dependency code.
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ec2.release_address(AllocationId=alloc),
                                           f"eip {alloc}", codes=("AuthFailure",)))
    return alloc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
