"""op-contract-describe-listeners."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-listeners"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeListeners reflects the listener's configured port/protocol/actions; bogus ARNs 404."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:

        raise AssertionError("need >=2 subnets in distinct AZs to create an ALB")

    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, subnet_ids)
    tg = _create_tg(ctx, vpc_id)
    listener = _create_listener(ctx, lb["LoadBalancerArn"], tg["TargetGroupArn"], port=8081)

    by_lb = elbv2.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]
    assert len(by_lb) == 1, f"expected exactly 1 listener on the ALB, got {len(by_lb)}: {by_lb}"
    assert by_lb[0]["ListenerArn"] == listener["ListenerArn"], (
        f"expected {listener['ListenerArn']!r}, got {by_lb[0]['ListenerArn']!r}"
    )
    assert by_lb[0]["Port"] == 8081, f"expected port 8081, got {by_lb[0]['Port']!r}"
    assert by_lb[0]["Protocol"] == "HTTP", f"expected protocol HTTP, got {by_lb[0]['Protocol']!r}"
    assert by_lb[0]["DefaultActions"][0]["TargetGroupArn"] == tg["TargetGroupArn"], (
        f"expected default action to forward to {tg['TargetGroupArn']!r}, "
        f"got {by_lb[0]['DefaultActions'][0]['TargetGroupArn']!r}"
    )

    by_arn = elbv2.describe_listeners(ListenerArns=[listener["ListenerArn"]])["Listeners"]
    assert len(by_arn) == 1 and by_arn[0]["ListenerArn"] == listener["ListenerArn"], (
        f"expected exactly [{listener['ListenerArn']!r}], got {by_arn!r}"
    )

    bogus_arn = listener["ListenerArn"][:-1] + ("0" if listener["ListenerArn"][-1] != "0" else "1")
    code, message = _error(lambda: elbv2.describe_listeners(ListenerArns=[bogus_arn]))
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "ListenerNotFound", f"expected not-found, got {code}"
    expected = "One or more listeners not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a bogus ListenerArn real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected ListenerNotFound, but the call SUCCEEDED and returned {result!r}")


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


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-alb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids[:2], Type="application")
    lb = resp["LoadBalancers"][0]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb["LoadBalancerArn"]))
    return lb


def _create_tg(ctx, vpc_id, name=None, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-tg-")
    params = dict(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance")
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg["TargetGroupArn"]))
    return tg


def _create_listener(ctx, lb_arn, tg_arn, port=80):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    listener = resp["Listeners"][0]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener["ListenerArn"]))
    return listener



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
