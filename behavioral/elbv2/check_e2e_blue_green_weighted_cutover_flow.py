"""e2e-blue-green-weighted-cutover-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-blue-green-weighted-cutover-flow"
GROUP = "e2e"
SERVICES = ["elbv2"]

_CIDR = "10.94.0.0/16"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Shifting a weighted-forward rule from blue to green keeps blue's target registered and
    blocks deleting blue with ResourceInUse; once dropped from the rule and drained, blue deletes.
    """
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    tagspec = lambda kind, name: {  # noqa: E731
        "ResourceType": kind,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{name}-")}],
    }

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=[tagspec("vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe(ctx, lambda: _delete_net(ctx, ec2, "delete_vpc", VpcId=vpc_id)))
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose 2 available AZs for ALB subnets")
    subnet_ids = []
    for i, az in enumerate(azs):
        sn = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.94.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[tagspec("subnet", f"subnet-{i}")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sn)
        ctx.on_cleanup(_safe(ctx, lambda sid=sn: _delete_net(ctx, ec2, "delete_subnet", SubnetId=sid)))

    lb_name = ctx.unique_name("sim2real-bg-alb-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnet_ids, Scheme="internal", Type="application",
        Tags=[{"Key": "Name", "Value": lb_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_safe(ctx, lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    lb_state = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active", timeout_s=180, interval_s=5,
        description="load balancer to reach active state",
    )
    assert lb_state == "active", f"load balancer never became active, last state={lb_state!r}"

    blue_name = ctx.unique_name("sim2real-blue-")
    blue_arn = elbv2.create_target_group(
        Name=blue_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "Name", "Value": blue_name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(_safe(ctx, lambda: elbv2.delete_target_group(TargetGroupArn=blue_arn)))
    # Shrink the deregistration delay so the post-deregister poll below stays bounded
    # (the default is 300s).
    elbv2.modify_target_group_attributes(
        TargetGroupArn=blue_arn, Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "10"}]
    )
    green_name = ctx.unique_name("sim2real-green-")
    green_arn = elbv2.create_target_group(
        Name=green_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
        Tags=[{"Key": "Name", "Value": green_name}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(_safe(ctx, lambda: elbv2.delete_target_group(TargetGroupArn=green_arn)))

    blue_ip = "10.94.0.50"
    green_ip = "10.94.1.50"
    elbv2.register_targets(TargetGroupArn=blue_arn, Targets=[{"Id": blue_ip, "Port": 80}])
    elbv2.register_targets(TargetGroupArn=green_arn, Targets=[{"Id": green_ip, "Port": 80}])

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "404", "ContentType": "text/plain"}}],
    )["Listeners"][0]["ListenerArn"]
    # The listener and its rule hold both target groups; deleting it first frees them for their teardowns.
    ctx.on_cleanup(_safe(ctx, lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn, Priority=5, Conditions=[{"Field": "path-pattern", "Values": ["/*"]}],
        Actions=[
            {
                "Type": "forward",
                "ForwardConfig": {
                    "TargetGroups": [
                        {"TargetGroupArn": blue_arn, "Weight": 100},
                        {"TargetGroupArn": green_arn, "Weight": 0},
                    ]
                },
            }
        ],
    )["Rules"][0]["RuleArn"]

    weights = _rule_weights(elbv2, rule_arn)
    assert weights == {blue_arn: 100, green_arn: 0}, f"initial weights not as configured: {weights}"

    health_before = elbv2.describe_target_health(TargetGroupArn=blue_arn)["TargetHealthDescriptions"]
    assert any(t["Target"]["Id"] == blue_ip for t in health_before), (
        f"blue target {blue_ip} not registered on {blue_arn}: {health_before}"
    )
    health_before_green = elbv2.describe_target_health(TargetGroupArn=green_arn)["TargetHealthDescriptions"]
    assert any(t["Target"]["Id"] == green_ip for t in health_before_green), (
        f"green target {green_ip} not registered on {green_arn}: {health_before_green}"
    )

    elbv2.modify_rule(
        RuleArn=rule_arn,
        Actions=[
            {
                "Type": "forward",
                "ForwardConfig": {
                    "TargetGroups": [
                        {"TargetGroupArn": blue_arn, "Weight": 0},
                        {"TargetGroupArn": green_arn, "Weight": 100},
                    ]
                },
            }
        ],
    )
    weights_after = _rule_weights(elbv2, rule_arn)
    assert weights_after == {blue_arn: 0, green_arn: 100}, f"weight cutover not reflected: {weights_after}"

    # Both target groups remain registered/associated even mid-cutover (weight
    # 0 stops traffic, it does not deregister anything).
    still_registered = elbv2.describe_target_health(TargetGroupArn=blue_arn)["TargetHealthDescriptions"]
    assert any(t["Target"]["Id"] == blue_ip for t in still_registered), (
        f"weight 0 must not deregister; blue target {blue_ip} missing from {blue_arn}: {still_registered}"
    )

    # The retired (blue) group is still referenced by the rule -> deletion
    # must be rejected until it is fully dropped from routing.
    code, message = _error(lambda: elbv2.delete_target_group(TargetGroupArn=blue_arn))
    assert code == "ResourceInUse", f"expected ResourceInUse deleting a rule-referenced target group, got {code!r}"
    expected_in_use = f"Target group '{blue_arn}' is currently in use by a listener or a rule"
    assert message == expected_in_use, f"expected message {expected_in_use!r}, got {message!r}"
    describe_blue_ok = elbv2.describe_target_groups(TargetGroupArns=[blue_arn])["TargetGroups"]
    assert describe_blue_ok and describe_blue_ok[0]["TargetGroupArn"] == blue_arn, (
        f"blue target group must still exist after its delete was rejected: {describe_blue_ok}"
    )

    # Fully cut over: drop blue from the rule's routing entirely.
    elbv2.modify_rule(
        RuleArn=rule_arn,
        Actions=[{"Type": "forward", "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": green_arn, "Weight": 100}]}}],
    )
    final_weights = _rule_weights(elbv2, rule_arn)
    assert final_weights == {green_arn: 100}, f"blue was not fully removed from routing: {final_weights}"

    elbv2.deregister_targets(TargetGroupArn=blue_arn, Targets=[{"Id": blue_ip, "Port": 80}])

    def _blue_target_count():
        return len(elbv2.describe_target_health(TargetGroupArn=blue_arn)["TargetHealthDescriptions"])

    remaining = _poll_until(
        _blue_target_count, lambda n: n == 0, timeout_s=60, interval_s=5,
        description="deregistered target to drain from the blue target group",
    )
    assert remaining == 0, f"blue target group still has {remaining} registered target(s) after drain"

    elbv2.delete_target_group(TargetGroupArn=blue_arn)
    gone_code, gone_message = _error(lambda: elbv2.describe_target_groups(TargetGroupArns=[blue_arn]))
    assert gone_code == "TargetGroupNotFound", f"expected TargetGroupNotFound after delete, got {gone_code!r}"
    expected_gone = "One or more target groups not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


# One deadline shared by all of the check's teardowns, inside the suite's 900 s cleanup budget.
_TEARDOWN_S = 840.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _safe(ctx, fn):
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s to the shared deadline, anything else raises."""
    def _wrapped():
        from botocore.exceptions import ClientError

        deadline = _deadline(ctx)
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _GONE:
                    return
                if code not in _IN_USE or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _error(fn):
    """Return (code, message) of the AWS error fn raises; raise AssertionError if it succeeds."""
    try:
        result = fn()
    except Exception as err:
        resp = getattr(err, "response", None)
        if resp is None:
            raise
        return resp.get("Error", {}).get("Code"), resp.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _rule_weights(elbv2, rule_arn: str) -> dict:
    rule = elbv2.describe_rules(RuleArns=[rule_arn])["Rules"][0]
    action = next(a for a in rule["Actions"] if a["Type"] == "forward")
    return {tg["TargetGroupArn"]: tg["Weight"] for tg in action["ForwardConfig"]["TargetGroups"]}


# A load balancer, endpoint, cluster, function or instance deletes asynchronously: its ENIs stay
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc
# fails with DependencyViolation. Wait (bounded) for the ENIs to go and retry inside that window.
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(ctx, client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = _deadline(ctx)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation at the teardown deadline; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


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
