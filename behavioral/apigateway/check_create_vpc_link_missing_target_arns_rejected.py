"""create-vpc-link-missing-target-arns-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-vpc-link-missing-target-arns-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink rejects an empty targetArns list (missing required target)."""
    apigw = ctx.client("apigateway")

    bad_name = ctx.unique_name("sim2real-vpclink-bad-")
    # Negative: targetArns present but empty -- structurally valid, semantically missing.
    code, message = _error(lambda: apigw.create_vpc_link(name=bad_name, targetArns=[]))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Need at least one target arn to create a vpc link", (
        f"unexpected BadRequestException message {message!r}"
    )

    # Effect absent: no vpc link with that name exists.
    links = apigw.get_vpc_links()["items"]
    assert all(existing_link["name"] != bad_name for existing_link in links), "vpc link leaked despite empty targetArns"

    # Positive control: a real NLB ARN succeeds.
    clock = _TeardownClock(_TEARDOWN_BUDGET_S)
    nlb_arn = _create_active_nlb(ctx, clock)
    good_name = ctx.unique_name("sim2real-vpclink-good-")
    vpc_link_id = apigw.create_vpc_link(name=good_name, targetArns=[nlb_arn])["id"]
    ctx.on_cleanup(lambda: _delete_vpc_link(apigw, vpc_link_id, clock))
    link = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert link["targetArns"] == [nlb_arn], f"expected targetArns=[{nlb_arn}], got {link['targetArns']}"


def _error(fn: Any) -> tuple:
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_active_nlb(ctx, clock) -> str:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    tag_value = ctx.unique_name("sim2real-apigw-nlb-")
    tags = [{"Key": "Name", "Value": tag_value}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/24", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, clock, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, clock, "delete_subnet", SubnetId=subnet_id))

    nlb_name = ctx.unique_name("sim2real-nlb-")[:32]
    nlb_arn = elbv2.create_load_balancer(
        Name=nlb_name, Subnets=[subnet_id], Scheme="internal", Type="network", Tags=tags
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_load_balancer(elbv2, nlb_arn, clock))

    deadline = time.monotonic() + 180.0
    state = None
    while time.monotonic() < deadline:
        lbs = elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"]
        state = lbs[0]["State"]["Code"]
        if state == "active":
            return nlb_arn
        time.sleep(5)
    raise AssertionError(f"NLB never reached active state (last state={state})")


#: The suite's 900 s cleanup budget, less a margin: the run's one teardown deadline.
_TEARDOWN_BUDGET_S = 840.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound")


class _TeardownClock:
    """The run's one teardown deadline, started by the first teardown that asks for it."""

    def __init__(self, budget_s: float) -> None:
        self.budget_s = budget_s
        self.end = None

    def deadline(self) -> float:
        if self.end is None:
            self.end = time.monotonic() + self.budget_s
        return self.end


def _delete_vpc_link(apigw, vpc_link_id, clock):
    """Delete the VPC link and wait until GetVpcLink answers NotFoundException: the link keeps the
    load balancer in use while it deletes. The PENDING refusal is retried every 2 s; anything else,
    or the run's teardown deadline, raises."""
    from botocore.exceptions import ClientError

    deadline = clock.deadline()
    while True:
        try:
            apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
            break
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "NotFoundException":
                return
            pending = error["Code"] == "BadRequestException" and "in PENDING" in error.get("Message", "")
            if not pending or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            status = apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"VPC link {vpc_link_id} is still {status} at the teardown deadline")
        time.sleep(2)


def _delete_load_balancer(elbv2, lb_arn, clock):
    """Delete the load balancer, retrying ResourceInUse (a VPC link still holds it) every 2 s, and
    wait until DescribeLoadBalancers answers LoadBalancerNotFound; raises at the run's deadline."""
    from botocore.exceptions import ClientError

    deadline = clock.deadline()
    while True:
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "LoadBalancerNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"load balancer {lb_arn} still listed at the teardown deadline")
        time.sleep(2)


def _delete_net(client, clock, op, **ident):
    """Run an EC2 network delete: a not-found answer is done; DependencyViolation (load balancer
    ENIs leave the VPC after their owner's delete returns) is retried every 2 s to the run's
    teardown deadline, then raised naming the ENIs still attached."""
    from botocore.exceptions import ClientError

    deadline = clock.deadline()
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _NET_GONE:
                return None
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation at the teardown deadline; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(2)


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
