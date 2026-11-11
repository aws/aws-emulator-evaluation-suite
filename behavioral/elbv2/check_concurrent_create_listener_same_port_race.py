"""concurrent-create-listener-same-port-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-create-listener-same-port-race"
GROUP = "concurrency"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateListener calls on the same load balancer and port
    result in exactly one listener existing; the loser fails with
    DuplicateListener, never two listeners on the same port."""
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids = _get_default_vpc_subnets(ctx)
    lb_arn = _create_alb(ctx, subnet_ids)

    def _create(body: str) -> tuple[str, Any]:
        try:
            resp = elbv2.create_listener(
                LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
                DefaultActions=[_fixed_response_action(body)],
            )
            return ("ok", resp["Listeners"][0]["ListenerArn"])
        except Exception as exc:  # noqa: BLE001 - classified by error code below
            message = (getattr(exc, "response", None) or {}).get("Error", {}).get("Message")
            return ("err", _error_code(exc), message)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(_create, "body-1")
        fut2 = pool.submit(_create, "body-2")
        result1 = fut1.result()
        result2 = fut2.result()

    outcomes = [result1, result2]
    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "err"]
    assert len(successes) == 1, f"expected exactly one winning CreateListener, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one losing CreateListener, got {outcomes}"
    assert failures[0][1] == "DuplicateListener", f"unexpected loser error code: {failures[0][1]}"
    loser_message = failures[0][2]
    assert loser_message == (
        f"A listener already exists on this port for this load balancer '{lb_arn}'"
    ), loser_message

    winner_arn = successes[0][1]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=winner_arn))

    listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    port_80 = [listener for listener in listeners if listener["Port"] == 80]
    assert len(port_80) == 1, f"expected exactly 1 listener on port 80, found {len(port_80)}"
    assert port_80[0]["ListenerArn"] == winner_arn, (
        f"expected surviving listener on port 80 to be the winner {winner_arn!r}, "
        f"found {port_80[0]['ListenerArn']!r}"
    )


def _error_code(exc: Any) -> str | None:
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


def _fixed_response_action(body: str) -> dict[str, Any]:
    return {
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": body},
    }


def _get_default_vpc_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an ALB for this check")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 AZs")
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids: list[str]) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-")[:32]
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_lb_active(ctx, lb_arn)
    return lb_arn


def _wait_lb_active(ctx, lb_arn: str, timeout_s: float = 240.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        if lb["State"]["Code"] == "active":
            return
        if lb["State"]["Code"] == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State']}")
        time.sleep(5)
    raise AssertionError("load balancer never became active in time")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
