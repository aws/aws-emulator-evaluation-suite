"""modify-load-balancer-attributes-idle-timeout-enforced."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "modify-load-balancer-attributes-idle-timeout-enforced"
GROUP = "server-side"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """idle_timeout.timeout_seconds defaults to 60 and a value of 90 set via
    ModifyLoadBalancerAttributes reads back unchanged; a non-numeric value fails with
    ValidationError and leaves the stored value intact."""
    elbv2 = ctx.client("elbv2")
    lb_arn = _create_alb(ctx)

    default_attrs = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
    }
    assert default_attrs.get("idle_timeout.timeout_seconds") == "60", (
        f"unexpected default idle_timeout.timeout_seconds: {default_attrs.get('idle_timeout.timeout_seconds')!r}"
    )

    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "idle_timeout.timeout_seconds", "Value": "90"}],
    )
    updated_attrs = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
    }
    assert updated_attrs["idle_timeout.timeout_seconds"] == "90", (
        f"idle_timeout.timeout_seconds not persisted: {updated_attrs.get('idle_timeout.timeout_seconds')!r}"
    )

    # A non-numeric value, because the documented upper bound is not reliably enforced
    # synchronously, while a structurally invalid value is.
    code, message = _error(
        lambda: elbv2.modify_load_balancer_attributes(
            LoadBalancerArn=lb_arn,
            Attributes=[{"Key": "idle_timeout.timeout_seconds", "Value": "not-a-number"}],
        )
    )
    # Real AWS returns the wire code without the "Exception" suffix of the botocore shape name.
    assert code == "ValidationError", f"expected a non-numeric idle_timeout value to be rejected, got {code}"
    expected = "The value of 'idle_timeout.timeout_seconds' must be a valid integer"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_attrs = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
    }
    assert still_attrs["idle_timeout.timeout_seconds"] == "90", (
        "the rejected invalid idle_timeout update was partially applied"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the non-numeric idle_timeout value to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _get_alb_network(ctx) -> tuple[str, list[str], str | None]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    chosen = list(by_az.values())[:2]
    if len(chosen) < 2:
        raise AssertionError("need subnets in at least 2 distinct AZs to create a load balancer")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, [s["SubnetId"] for s in chosen], sg_id


def _alb_name(ctx, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:32].rstrip("-")


def _create_alb(ctx) -> str:
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids, sg_id = _get_alb_network(ctx)
    kwargs: dict[str, Any] = dict(
        Name=_alb_name(ctx, "idle"),
        Subnets=subnet_ids,
        Type="application",
        Scheme="internet-facing",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    if sg_id:
        kwargs["SecurityGroups"] = [sg_id]
    lb = elbv2.create_load_balancer(**kwargs)["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    return lb_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
