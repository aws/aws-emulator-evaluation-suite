"""op-contract-create-load-balancer."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-load-balancer"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLoadBalancer returns a provisioning ALB that reaches active; duplicate names are rejected."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:

        raise AssertionError("need >=2 subnets in distinct AZs to create an ALB")

    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")
    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids[:2], Type="application", Tags=tags_kv)
    lb = resp["LoadBalancers"][0]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb["LoadBalancerArn"]))

    assert lb["LoadBalancerName"] == name, f"expected name {name!r}, got {lb['LoadBalancerName']!r}"
    assert lb["Type"] == "application", f"expected type application, got {lb['Type']!r}"
    assert lb["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {lb['VpcId']!r}"
    assert lb["DNSName"], "DNSName should be populated on create"
    assert lb["LoadBalancerArn"].startswith("arn:aws:elasticloadbalancing:"), (
        f"unexpected ARN shape: {lb['LoadBalancerArn']!r}"
    )

    final_state = _wait_for_lb_state(ctx, lb["LoadBalancerArn"], {"active", "active_impaired", "failed"})
    assert final_state == "active", f"expected ALB to become active, got {final_state}"

    # A byte-for-byte identical CreateLoadBalancer request (same name/subnets/type) is treated as
    # idempotent by real AWS and returns the existing LB rather than erroring; the duplicate-name
    # rejection only fires when the name collides with a DIFFERENT configuration (here: a
    # different Scheme), which is what actually exercises the error path.
    code, message = _error(
        lambda: elbv2.create_load_balancer(
            Name=name, Subnets=subnet_ids[:2], Type="application", Scheme="internal"
        )
    )
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "DuplicateLoadBalancerName", f"expected duplicate-name error, got {code}"
    expected = f"A load balancer with the same name '{name}' exists, but with different settings"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The forbidden effect (a second load balancer under this name) did not happen: an
    # independent read still shows exactly the one load balancer this check created.
    listing = elbv2.describe_load_balancers(Names=[name])["LoadBalancers"]
    assert len(listing) == 1 and listing[0]["LoadBalancerArn"] == lb["LoadBalancerArn"], (
        f"expected exactly one load balancer {lb['LoadBalancerArn']!r} named {name!r} after the "
        f"rejected duplicate create, got {listing!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    return vpc_id, list(by_az.values())


def _wait_for_lb_state(ctx, lb_arn, target_states, timeout_s=240.0, interval_s=10.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        lbs = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"]
        last = lbs[0]["State"]["Code"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"load balancer never reached {target_states}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
