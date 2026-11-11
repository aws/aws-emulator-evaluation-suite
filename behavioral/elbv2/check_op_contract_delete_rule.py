"""op-contract-delete-rule."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-rule"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRule removes a custom rule, and the removal is independently observable both from
    the listener's rule list and from a direct lookup by ARN; deleting a listener's default rule
    is rejected and leaves the default rule in place."""
    vpc_id, subnet_ids = _vpc_and_subnets(ctx)
    if len(subnet_ids) < 2:
        raise AssertionError("need >=2 subnets in distinct AZs to create an ALB")

    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, subnet_ids)
    tg = _create_tg(ctx, vpc_id)
    listener = _create_listener(ctx, lb["LoadBalancerArn"], tg["TargetGroupArn"])

    rule = elbv2.create_rule(
        ListenerArn=listener["ListenerArn"],
        Conditions=[{"Field": "path-pattern", "Values": ["/api/*"]}],
        Priority=10,
        Actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Rules"][0]
    rule_arn = rule["RuleArn"]

    resp = elbv2.delete_rule(RuleArn=rule_arn)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 from DeleteRule, got {status}"
    remaining = elbv2.describe_rules(ListenerArn=listener["ListenerArn"])["Rules"]
    assert all(r["RuleArn"] != rule_arn for r in remaining), "custom rule should be gone from the listener's rule list"

    lookup_code, lookup_message = _error(lambda: elbv2.describe_rules(RuleArns=[rule_arn]))
    assert lookup_code == "RuleNotFound", f"expected RuleNotFound looking up the deleted rule by ARN, got {lookup_code}"
    expected = "One or more rules not found"
    assert lookup_message == expected, f"expected message {expected!r}, got {lookup_message!r}"

    modify_code, modify_message = _error(lambda: elbv2.modify_rule(
        RuleArn=rule_arn, Conditions=[{"Field": "path-pattern", "Values": ["/still-dead/*"]}],
    ))
    assert modify_code == "RuleNotFound", f"expected RuleNotFound modifying the deleted rule, got {modify_code}"
    expected = f"Rule '{rule_arn}' not found"
    assert modify_message == expected, f"expected message {expected!r}, got {modify_message!r}"

    default_rule = next(r for r in remaining if r["IsDefault"])
    default_arn = default_rule["RuleArn"]
    code, message = _error(lambda: elbv2.delete_rule(RuleArn=default_arn))
    # Real AWS's ELBv2 API returns the error type WITHOUT the "Exception" suffix on the wire
    # (unlike the shape name used by the botocore model / docs).
    assert code == "OperationNotPermitted", f"expected default-rule rejection, got {code}"
    expected = f"Default rule '{default_arn}' cannot be deleted"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_reject = elbv2.describe_rules(ListenerArn=listener["ListenerArn"])["Rules"]
    assert any(r["RuleArn"] == default_arn for r in after_reject), (
        "default rule must still exist after the rejected delete attempt"
    )


# ===== helpers =====
_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _vpc_and_subnets(ctx, num_subnets=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) >= num_subnets:
        return vpc_id, subnet_ids
    return _create_vpc_and_subnets(ctx, num_subnets)


def _create_vpc_and_subnets(ctx, num_subnets):
    ec2 = ctx.client("ec2")
    name_tags = _TAGS + [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]
    vpc = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": name_tags}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i % len(azs)]["ZoneName"]
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.77.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]
        subnet_ids.append(subnet["SubnetId"])
        ctx.on_cleanup(lambda sid=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-alb-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids[:2], Type="application", Scheme="internal", Tags=_TAGS,
    )
    lb = resp["LoadBalancers"][0]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb["LoadBalancerArn"]))
    return lb


def _create_tg(ctx, vpc_id, name=None, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-tg-")
    params = dict(Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance", Tags=_TAGS)
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg["TargetGroupArn"]))
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
