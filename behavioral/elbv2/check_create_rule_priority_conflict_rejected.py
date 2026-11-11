"""create-rule-priority-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rule-priority-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRule with a priority already used by another rule on the same listener is rejected
    with PriorityInUse, and no second rule is created at that priority. Removing the conflicting
    rule frees the priority, and the identical create now succeeds."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    tg = _create_target_group(ctx, net["vpc_id"])

    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    first = elbv2.create_rule(
        ListenerArn=listener["ListenerArn"],
        Priority=42,
        Conditions=[{"Field": "path-pattern", "Values": ["/first/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        Tags=_tags_kv(),
    )["Rules"][0]
    first_arn = first["RuleArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_rule(RuleArn=first_arn)))

    code, message = _error(
        lambda: elbv2.create_rule(
            ListenerArn=listener["ListenerArn"],
            Priority=42,
            Conditions=[{"Field": "path-pattern", "Values": ["/second/*"]}],
            Actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
            Tags=_tags_kv(),
        )
    )
    assert code == "PriorityInUse", f"expected PriorityInUse, got {code!r}"
    assert message == "Priority '42' is currently in use", f"MSG={message!r}"

    rules = elbv2.describe_rules(ListenerArn=listener["ListenerArn"])["Rules"]
    custom_rules = [r for r in rules if not r["IsDefault"]]
    assert len(custom_rules) == 1, f"the rejected create must not have created a second rule: {custom_rules}"
    assert custom_rules[0]["Conditions"][0]["Values"] == ["/first/*"], (
        f"expected the surviving rule to still be /first/*, got {custom_rules[0]['Conditions']}"
    )

    # restore: removing the conflicting rule frees priority 42 for an identical retry
    elbv2.delete_rule(RuleArn=first_arn)
    second = elbv2.create_rule(
        ListenerArn=listener["ListenerArn"],
        Priority=42,
        Conditions=[{"Field": "path-pattern", "Values": ["/second/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        Tags=_tags_kv(),
    )["Rules"][0]
    second_arn = second["RuleArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_rule(RuleArn=second_arn)))

    rules_after = elbv2.describe_rules(ListenerArn=listener["ListenerArn"])["Rules"]
    custom_after = [r for r in rules_after if not r["IsDefault"]]
    assert len(custom_after) == 1, f"expected exactly one custom rule after restore, got {custom_after}"
    assert custom_after[0]["RuleArn"] == second_arn, (
        f"expected the restored priority-42 rule to be the new rule, got {custom_after[0]['RuleArn']}"
    )
    assert custom_after[0]["Conditions"][0]["Values"] == ["/second/*"], (
        f"expected the restored rule to be /second/*, got {custom_after[0]['Conditions']}"
    )


# ===== helpers =====
_GONE = {"LoadBalancerNotFound", "TargetGroupNotFound", "ListenerNotFound", "RuleNotFound",
         "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}
_BUSY = {"ResourceInUse", "ResourceInUseException"}


def _safe(fn, timeout_s=120.0):
    """Teardown: done once the resource is gone; retries while a dependency is still being released."""
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _GONE:
                return
            if code not in _BUSY or _time.monotonic() >= deadline:
                raise
        _time.sleep(2)


def _error(fn) -> tuple[str, str]:
    """Run ``fn``, which AWS refuses, and return the refusal's (code, message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _default_vpc_and_subnets(ctx):
    """Create-or-adopt: use the account's default VPC if it has one, otherwise provision a
    throwaway VPC+subnets so the check does not depend on ambient environment state."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s)
        if len(by_az) >= 2:
            chosen = list(by_az.values())[:2]
            return {
                "vpc_id": vpc_id,
                "subnet_ids": [s["SubnetId"] for s in chosen],
                "subnet_cidrs": [s["CidrBlock"] for s in chosen],
            }

    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-vpc-")}],
    )
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids, subnet_cidrs = [], []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        cidr = f"10.99.{i}.0/24"
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))
        subnet_ids.append(subnet_id)
        subnet_cidrs.append(cidr)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "subnet_cidrs": subnet_cidrs}


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application", Tags=_tags_kv())
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip", "Tags": _tags_kv()}
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
    return tg


# Network teardown: load balancers and similar resources delete asynchronously and leave ENIs in
# the subnet or security group, so an immediate delete fails with DependencyViolation. Wait for
# the ENIs (bounded, shared by all of one check's network deletes), then retry within the window.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
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
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
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
