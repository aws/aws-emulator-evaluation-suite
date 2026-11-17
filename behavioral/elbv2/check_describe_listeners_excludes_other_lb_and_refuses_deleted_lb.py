"""describe-listeners-excludes-other-lb-and-refuses-deleted-lb."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-listeners-excludes-other-lb-and-refuses-deleted-lb"
GROUP = "listener-lifecycle"
SERVICES = ["elbv2"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    return vpc_id, list(by_az.values())


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
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


def _create_alb(ctx, subnet_ids):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")[:32].rstrip("-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids[:2], Scheme="internal", Type="application")
    lb = resp["LoadBalancers"][0]
    ctx.on_cleanup(lambda: _teardown_lb(elbv2, lb["LoadBalancerArn"]))
    return lb


def _teardown_lb(elbv2, arn):
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _create_tg(ctx, vpc_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")[:32].rstrip("-")
    resp = elbv2.create_target_group(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance")
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg["TargetGroupArn"]))
    return tg


def _create_listener(ctx, lb_arn, tg_arn, port):
    elbv2 = ctx.client("elbv2")
    resp = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    listener = resp["Listeners"][0]
    ctx.on_cleanup(lambda: _teardown_listener(elbv2, listener["ListenerArn"]))
    return listener


def _teardown_listener(elbv2, arn):
    try:
        elbv2.delete_listener(ListenerArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ListenerNotFound":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeListeners filtered by LoadBalancerArn excludes another load balancer's listener,
    ListenerArns from two load balancers returns both, and a deleted load balancer's ARN 404s.
    """
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:
        raise AssertionError("need >=2 subnets in distinct AZs to create an ALB")

    elbv2 = ctx.client("elbv2")

    lb_a = _create_alb(ctx, subnet_ids)
    tg_a = _create_tg(ctx, vpc_id)
    listener_a = _create_listener(ctx, lb_a["LoadBalancerArn"], tg_a["TargetGroupArn"], port=80)

    lb_b = _create_alb(ctx, subnet_ids)
    tg_b = _create_tg(ctx, vpc_id)
    listener_b = _create_listener(ctx, lb_b["LoadBalancerArn"], tg_b["TargetGroupArn"], port=8080)

    by_a = elbv2.describe_listeners(LoadBalancerArn=lb_a["LoadBalancerArn"])["Listeners"]
    assert [l["ListenerArn"] for l in by_a] == [listener_a["ListenerArn"]], (
        f"DescribeListeners(LoadBalancerArn=A) expected exactly [{listener_a['ListenerArn']!r}], "
        f"got {[l['ListenerArn'] for l in by_a]!r}"
    )

    by_b = elbv2.describe_listeners(LoadBalancerArn=lb_b["LoadBalancerArn"])["Listeners"]
    assert [l["ListenerArn"] for l in by_b] == [listener_b["ListenerArn"]], (
        f"DescribeListeners(LoadBalancerArn=B) expected exactly [{listener_b['ListenerArn']!r}], "
        f"got {[l['ListenerArn'] for l in by_b]!r}"
    )

    by_both_arns = elbv2.describe_listeners(
        ListenerArns=[listener_a["ListenerArn"], listener_b["ListenerArn"]]
    )["Listeners"]
    assert {l["ListenerArn"] for l in by_both_arns} == {listener_a["ListenerArn"], listener_b["ListenerArn"]}, (
        f"DescribeListeners(ListenerArns=[A,B]) expected exactly {{A, B}}, "
        f"got {[l['ListenerArn'] for l in by_both_arns]!r}"
    )
    assert len(by_both_arns) == 2, f"expected exactly 2 listeners, got {len(by_both_arns)}: {by_both_arns!r}"

    lb_b_arn = lb_b["LoadBalancerArn"]
    elbv2.delete_load_balancer(LoadBalancerArn=lb_b_arn)

    def _probe():
        try:
            return _error(lambda: elbv2.describe_listeners(LoadBalancerArn=lb_b_arn))
        except AssertionError:
            return None

    deadline = time.monotonic() + 60
    code = message = None
    while time.monotonic() < deadline:
        result = _probe()
        if result is not None:
            code, message = result
            break
        time.sleep(3)
    assert code is not None, "the deleted load balancer's ARN still resolved via DescribeListeners after 60s"
    assert code == "LoadBalancerNotFound", f"expected LoadBalancerNotFound, got {code!r}"
    expected_message = f"Load balancer '{lb_b_arn}' not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the surviving load balancer's listener is unaffected by the other's deletion.
    by_a_after = elbv2.describe_listeners(LoadBalancerArn=lb_a["LoadBalancerArn"])["Listeners"]
    assert [l["ListenerArn"] for l in by_a_after] == [listener_a["ListenerArn"]], (
        f"after deleting load balancer B, DescribeListeners(LoadBalancerArn=A) expected exactly "
        f"[{listener_a['ListenerArn']!r}], got {[l['ListenerArn'] for l in by_a_after]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
