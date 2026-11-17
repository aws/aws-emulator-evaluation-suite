"""vpc-endpoint-service-configuration-accepts-only-network-load-balancers."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-endpoint-service-configuration-accepts-only-network-load-balancers"
GROUP = "privatelink"
SERVICES = ["ec2", "elbv2"]

#: An internal load balancer leaves `provisioning` well inside this window.
_LB_DEADLINE_S = 600

#: Dependents (the load balancer's ENIs) release into the subnets before they can be deleted.
_TEARDOWN_DEADLINE_S = 480


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PrivateLink endpoint service configuration can be backed by a Network Load Balancer, and
    refuses an Application Load Balancer ARN in the same field, leaving no configuration behind.

    Reference: https://docs.aws.amazon.com/vpc/latest/privatelink/create-endpoint-service.html
    """
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")
    tok = ctx.unique_name("sim2real-vpces-")
    net = _network(ctx, tok)
    sg = _no_ingress_sg(ctx, tok, net["vpc"])

    nlb = _load_balancer(ctx, tok + "-n", "network", net["subnets"])
    alb = _load_balancer(ctx, tok + "-a", "application", net["subnets"], security_groups=[sg])
    _wait_active(elb, nlb)
    _wait_active(elb, alb)

    bad_id, code, msg = _attempt_configuration(ec2, ctx, NetworkLoadBalancerArns=[alb],
                                               AcceptanceRequired=True)
    assert bad_id is None, f"an endpoint service configuration backed by an ALB was created: {bad_id!r}"
    expected_bad = ("InvalidNetworkLoadBalancerArn.Malformed", None)
    assert (code, msg) == expected_bad, (
        f"ALB-backed endpoint service configuration: got {(code, msg)!r}, want {expected_bad!r}")

    good_id, code, msg = _attempt_configuration(
        ec2, ctx, NetworkLoadBalancerArns=[nlb], AcceptanceRequired=True,
        TagSpecifications=[{"ResourceType": "vpc-endpoint-service",
                            "Tags": [{"Key": "sim2real", "Value": tok}]}])
    assert code is None, f"NLB-backed endpoint service configuration was refused: {code!r} ({msg!r})"

    cfg = ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[good_id])[
        "ServiceConfigurations"][0]
    assert cfg["NetworkLoadBalancerArns"] == [nlb], (
        f"the configuration names {cfg['NetworkLoadBalancerArns']!r}, not the NLB {nlb!r}")
    assert [t["ServiceType"] for t in cfg["ServiceType"]] == ["Interface"], (
        f"an NLB-backed configuration reports service type {cfg['ServiceType']!r}, expected Interface")
    got_zones = sorted(cfg["AvailabilityZones"])
    assert got_zones == sorted(net["azs"]), (
        f"the configuration's availability zones are {got_zones!r}, expected {sorted(net['azs'])!r}")
    assert good_id.startswith("vpce-svc-"), f"service id {good_id!r} does not look minted"


def _attempt_configuration(ec2, ctx, **kw):
    """Create a configuration; on unexpected success, register its cleanup before reporting it.

    Returns ``(service_id, None, None)`` on success or ``(None, code, message)`` on refusal.
    """
    try:
        cfg = ec2.create_vpc_endpoint_service_configuration(**kw)["ServiceConfiguration"]
    except ClientError as exc:
        return None, exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    service_id = cfg["ServiceId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))
    return service_id, None, None


def _wait_active(elb, arn: str) -> None:
    """Poll a load balancer to its terminal `active` state."""
    deadline = time.monotonic() + _LB_DEADLINE_S
    while True:
        state = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"]
        if state == "active":
            return
        assert state == "provisioning", f"load balancer {arn} left provisioning as {state!r}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {arn} still {state!r} after {_LB_DEADLINE_S}s")
        time.sleep(5)


def _tagspec(kind: str, name: str) -> list[dict]:
    return [{"ResourceType": kind,
             "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "vpces"}]}]


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


def _usable_azs(ctx, count: int) -> list[str]:
    """``count`` distinct available AZs; no instances are launched, so no type offering applies."""
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(zones) >= count, f"only {len(zones)} available AZ(s), need {count}: {zones!r}"
    return zones[:count]


def _network(ctx, tok: str) -> dict:
    """A VPC with two subnets in two AZs, no internet gateway: both load balancers are internal."""
    ec2 = ctx.client("ec2")
    azs = _usable_azs(ctx, 2)
    vpc = ec2.create_vpc(CidrBlock="172.31.0.0/16",
                         TagSpecifications=_tagspec("vpc", tok))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ec2.delete_vpc(VpcId=vpc), f"vpc {vpc}"))
    subnets = []
    for i, az in enumerate(azs):
        sn = ec2.create_subnet(VpcId=vpc, CidrBlock=f"172.31.{i}.0/24", AvailabilityZone=az,
                               TagSpecifications=_tagspec("subnet", tok))["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sn=sn: _retry_teardown(lambda: ec2.delete_subnet(SubnetId=sn),
                                                     f"subnet {sn}"))
        subnets.append(sn)
    return {"vpc": vpc, "subnets": subnets, "azs": azs}


def _no_ingress_sg(ctx, tok: str, vpc: str) -> str:
    """A security group with no custom ingress, for the internal ALB."""
    ec2 = ctx.client("ec2")
    sg = ec2.create_security_group(GroupName=tok, Description=tok, VpcId=vpc,
                                   TagSpecifications=_tagspec("security-group", tok))["GroupId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: ec2.delete_security_group(GroupId=sg), f"sg {sg}"))
    return sg


def _load_balancer(ctx, name: str, kind: str, subnets: list[str], *,
                   security_groups: list[str] | None = None) -> str:
    elb = ctx.client("elbv2")
    kw = {"Name": name, "Subnets": subnets, "Scheme": "internal", "Type": kind,
         "Tags": [{"Key": "sim2real", "Value": "vpces"}]}
    if security_groups is not None:
        kw["SecurityGroups"] = security_groups
    arn = elb.create_load_balancer(**kw)["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: elb.delete_load_balancer(LoadBalancerArn=arn),
                                           f"load balancer {arn}", codes=()))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
