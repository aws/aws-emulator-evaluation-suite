"""create-load-balancer-same-az-subnets-rejected."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-load-balancer-same-az-subnets-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2", "ec2"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")


def _free_cidr_pair(ec2, vpc_id: str, vpc_cidr: str, *, prefixlen: int = 25) -> list[str]:
    """Two adjacent ``/prefixlen`` blocks of ``vpc_cidr`` that no subnet in ``vpc_id`` occupies."""
    used = [
        ipaddress.ip_network(s["CidrBlock"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]
    candidates = ipaddress.ip_network(vpc_cidr).subnets(new_prefix=prefixlen)
    free: list[str] = []
    for candidate in candidates:
        if not any(candidate.overlaps(u) for u in used):
            free.append(str(candidate))
            if len(free) == 2:
                return free
    raise AssertionError(f"no two free /{prefixlen} blocks of {vpc_cidr} in {vpc_id}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An ALB needs subnets in at least two different Availability Zones; two subnets that
    share one zone are refused, and the load balancer never comes to exist.
    """
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    network = ctx.network()

    cidr_a, cidr_b = _free_cidr_pair(ec2, network.vpc_id, network.cidr)
    az = network.availability_zones[0]
    same_az_subnets = []
    for cidr in (cidr_a, cidr_b):
        subnet_id = ec2.create_subnet(
            VpcId=network.vpc_id, CidrBlock=cidr, AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        same_az_subnets.append(subnet_id)

    bad_name = ctx.unique_name("sim2real-behav-lb-")
    try:
        elbv2.create_load_balancer(
            Name=bad_name, Subnets=same_az_subnets, Type="application", Scheme="internal",
        )
    except ClientError as exc:
        err = exc.response["Error"]
        code, message = err["Code"], err.get("Message")
    else:
        # Unexpected success: register cleanup before asserting failure so nothing leaks.
        unexpected = elbv2.describe_load_balancers(Names=[bad_name])["LoadBalancers"][0]
        ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=unexpected["LoadBalancerArn"]))
        raise AssertionError(f"expected the call to be refused, but it succeeded: {unexpected!r}")
    assert code == "InvalidConfigurationRequest", (
        f"expected InvalidConfigurationRequest, got {code!r}: {message!r}"
    )
    assert message == "A load balancer cannot be attached to multiple subnets in the same Availability Zone", (
        f"unexpected refusal message: {message!r}"
    )

    try:
        elbv2.describe_load_balancers(Names=[bad_name])
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "LoadBalancerNotFound", (
            f"expected LoadBalancerNotFound for the never-created {bad_name!r}, got {err['Code']!r}"
        )
        assert err["Message"] == f"Load balancers '[{bad_name}]' not found", (
            f"unexpected not-found message: {err['Message']!r}"
        )
    else:
        raise AssertionError(f"load balancer {bad_name!r} unexpectedly exists after a rejected create")

    good_subnet_ids = network.subnet_ids[:2]
    good_name = ctx.unique_name("sim2real-behav-lb-")
    good_lb = elbv2.create_load_balancer(
        Name=good_name, Subnets=good_subnet_ids, Type="application", Scheme="internal",
    )["LoadBalancers"][0]
    good_arn = good_lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=good_arn))
    good_lb = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[good_arn])["LoadBalancers"][0],
        lambda lb: lb["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=180.0, interval_s=3.0,
        description=f"load balancer {good_arn} reaching a terminal state",
    )
    assert good_lb["State"]["Code"] == "active", (
        f"positive control: two subnets in distinct AZs {good_subnet_ids!r} settled in "
        f"{good_lb['State']!r}, expected 'active'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
