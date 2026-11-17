"""create-listener-network-load-balancer-listener-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-listener-network-load-balancer-listener-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]

_MAX_LISTENERS = 50


def _teardown(undo, *not_found: str):
    """Run ``undo()``; a failed delete raises unless its code is one of ``not_found``."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _refused(fn):
    """The (code, message) ``fn`` is refused with. Raises, naming the result, on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _listener_arns(elbv2, lb_arn):
    arns = []
    for page in elbv2.get_paginator("describe_listeners").paginate(LoadBalancerArn=lb_arn):
        arns.extend(l["ListenerArn"] for l in page["Listeners"])
    return sorted(arns)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Network Load Balancer accepts at most 50 listeners: the 51st CreateListener is refused
    with the exact over-limit error and the set of listeners stays unchanged, while freeing one
    slot lets the identical call succeed."""
    elbv2 = ctx.client("elbv2")
    net = ctx.network()
    subnets = net.subnet_ids[:2]
    assert len(subnets) == 2, f"the run's network has {len(subnets)} subnet(s), an NLB needs two"

    tg_name = ctx.unique_name("sim2real-nlblim-tg-")[:32].rstrip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="TCP", Port=80, VpcId=net.vpc_id, TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn), "TargetGroupNotFound"))

    lb_name = ctx.unique_name("sim2real-nlblim-")[:32].rstrip("-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Type="network", Scheme="internal", Subnets=subnets,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), "LoadBalancerNotFound"))

    action = [{"Type": "forward", "TargetGroupArn": tg_arn}]
    listener_arns = []
    for port in range(1, _MAX_LISTENERS + 1):
        arn = elbv2.create_listener(
            LoadBalancerArn=lb_arn, Protocol="TCP", Port=port, DefaultActions=action,
        )["Listeners"][0]["ListenerArn"]
        listener_arns.append(arn)
        ctx.on_cleanup(_teardown(lambda arn=arn: elbv2.delete_listener(ListenerArn=arn), "ListenerNotFound"))
    assert _listener_arns(elbv2, lb_arn) == sorted(listener_arns), (
        f"expected {_MAX_LISTENERS} listeners, the load balancer lists {_listener_arns(elbv2, lb_arn)!r}"
    )

    overflow_port = _MAX_LISTENERS + 1
    code, message = _refused(lambda: elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="TCP", Port=overflow_port, DefaultActions=action,
    ))
    assert code == "TooManyListeners", f"expected TooManyListeners for the 51st listener, got {code!r}"
    expected_message = f"The maximum number of listeners on load balancer '{lb_arn}' has been reached"
    assert message == expected_message, f"MSG={message!r}"

    assert _listener_arns(elbv2, lb_arn) == sorted(listener_arns), (
        f"the listener set changed after the refusal: {_listener_arns(elbv2, lb_arn)!r}"
    )

    freed_arn = listener_arns.pop()
    elbv2.delete_listener(ListenerArn=freed_arn)
    replacement_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="TCP", Port=overflow_port, DefaultActions=action,
    )["Listeners"][0]["ListenerArn"]
    listener_arns.append(replacement_arn)
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_listener(ListenerArn=replacement_arn), "ListenerNotFound"))
    assert _listener_arns(elbv2, lb_arn) == sorted(listener_arns), (
        f"expected the freed slot to hold the replacement listener, got {_listener_arns(elbv2, lb_arn)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
