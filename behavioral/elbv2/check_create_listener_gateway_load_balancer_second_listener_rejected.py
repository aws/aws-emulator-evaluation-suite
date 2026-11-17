"""create-listener-gateway-load-balancer-second-listener-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-listener-gateway-load-balancer-second-listener-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


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
    return sorted(l["ListenerArn"] for l in elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Gateway Load Balancer, whose listener takes no port or protocol, accepts only one: a
    second CreateListener naming a different target group is refused and no second listener
    appears, while deleting the first lets the identical call succeed."""
    elbv2 = ctx.client("elbv2")
    net = ctx.network()
    subnet_id = net.subnet_ids[0]

    tg_name = ctx.unique_name("sim2real-gwlim-tg1-")[:32].rstrip("-")
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="GENEVE", Port=6081, VpcId=net.vpc_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn), "TargetGroupNotFound"))
    tg2_name = ctx.unique_name("sim2real-gwlim-tg2-")[:32].rstrip("-")
    tg2_arn = elbv2.create_target_group(
        Name=tg2_name, Protocol="GENEVE", Port=6081, VpcId=net.vpc_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_target_group(TargetGroupArn=tg2_arn), "TargetGroupNotFound"))

    lb_name = ctx.unique_name("sim2real-gwlim-")[:32].rstrip("-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Type="gateway", SubnetMappings=[{"SubnetId": subnet_id}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), "LoadBalancerNotFound"))

    first_action = [{"Type": "forward", "TargetGroupArn": tg_arn}]
    second_action = [{"Type": "forward", "TargetGroupArn": tg2_arn}]
    first_arn = elbv2.create_listener(LoadBalancerArn=lb_arn, DefaultActions=first_action)["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_listener(ListenerArn=first_arn), "ListenerNotFound"))
    assert _listener_arns(elbv2, lb_arn) == [first_arn], (
        f"expected exactly the first listener, got {_listener_arns(elbv2, lb_arn)!r}"
    )

    code, message = _refused(lambda: elbv2.create_listener(LoadBalancerArn=lb_arn, DefaultActions=second_action))
    assert code == "DuplicateListener", f"expected DuplicateListener for a second gateway listener, got {code!r}"
    expected_message = f"A listener already exists on this port for this load balancer '{lb_arn}'"
    assert message == expected_message, f"MSG={message!r}"

    assert _listener_arns(elbv2, lb_arn) == [first_arn], (
        f"a second listener exists after the refusal: {_listener_arns(elbv2, lb_arn)!r}"
    )

    elbv2.delete_listener(ListenerArn=first_arn)
    second_arn = elbv2.create_listener(LoadBalancerArn=lb_arn, DefaultActions=second_action)["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_listener(ListenerArn=second_arn), "ListenerNotFound"))
    assert _listener_arns(elbv2, lb_arn) == [second_arn], (
        f"expected exactly the replacement listener, got {_listener_arns(elbv2, lb_arn)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
