"""modify-listener-attributes-invalid-config-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-listener-attributes-invalid-config-fails"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyListenerAttributes with an NLB-only attribute on an ALB listener raises
    InvalidConfigurationRequestException, leaves the listener's existing attributes untouched, and
    the same listener still accepts a valid attribute change afterward."""
    subnets = _get_default_subnets(ctx, count=2)
    lb_arn = _create_lb(ctx, subnets["subnet_ids"])
    _wait_lb_active(ctx, lb_arn)

    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "200"}}
        ],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-listener-")}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    def _attrs():
        return {
            a["Key"]: a["Value"]
            for a in elbv2.describe_listener_attributes(ListenerArn=listener_arn)["Attributes"]
        }

    before = _attrs()
    assert "tcp.idle_timeout.seconds" not in before, (
        f"an ALB listener should not expose tcp.idle_timeout.seconds, but it is present: {before!r}"
    )

    # tcp.idle_timeout.seconds is only supported by NLB/GWLB listeners, not ALB.
    code, message = _error(
        lambda: elbv2.modify_listener_attributes(
            ListenerArn=listener_arn,
            Attributes=[{"Key": "tcp.idle_timeout.seconds", "Value": "100"}],
        )
    )
    assert code == "InvalidConfigurationRequest", (
        f"expected InvalidConfigurationRequestException, got {code!r}"
    )
    expected = "The provided listener attribute is not supported"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: an independent read at the destination shows the rejected call changed
    # nothing, and it still did not add the NLB-only key.
    after_reject = _attrs()
    assert after_reject == before, (
        f"the rejected ModifyListenerAttributes call changed listener attributes: "
        f"before={before!r} after={after_reject!r}"
    )
    assert "tcp.idle_timeout.seconds" not in after_reject, (
        f"the rejected call still resulted in tcp.idle_timeout.seconds being stored: {after_reject!r}"
    )

    # Positive control: the same listener still accepts a valid attribute change, so the rejection
    # above is attributable to the NLB-only key and not to a listener/account that rejects every
    # ModifyListenerAttributes call.
    valid_key = "routing.http.response.server.enabled"
    target_value = "false" if before.get(valid_key) != "false" else "true"
    elbv2.modify_listener_attributes(
        ListenerArn=listener_arn, Attributes=[{"Key": valid_key, "Value": target_value}]
    )
    after_valid = _attrs()
    assert after_valid[valid_key] == target_value, (
        f"a valid attribute change on the same listener did not take effect: "
        f"expected {valid_key}={target_value!r}, got {after_valid.get(valid_key)!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected ModifyListenerAttributes to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _get_default_subnets(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = sorted(by_az.values())
    if len(ids) < count:
        raise AssertionError("not enough distinct-AZ subnets in shared network for this check")
    return {"vpc_id": vpc_id, "subnet_ids": ids[:count]}


def _safe_delete_lb(ctx, arn):
    elbv2 = ctx.client("elbv2")
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _create_lb(ctx, subnet_ids, scheme="internal", lb_type="application"):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-elbv2-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme=scheme,
        Type=lb_type,
        Tags=[{"Key": "Name", "Value": name}],
    )
    arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe_delete_lb(ctx, arn))
    return arn


def _wait_lb_active(ctx, arn, timeout_s=180.0, interval_s=5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        desc = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
        state = desc["State"]["Code"]
        if state in ("active", "active_impaired", "failed"):
            return state
        time.sleep(interval_s)
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
