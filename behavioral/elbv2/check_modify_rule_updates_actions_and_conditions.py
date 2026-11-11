"""modify-rule-updates-actions-and-conditions."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "modify-rule-updates-actions-and-conditions"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyRule replaces Actions/Conditions on a non-default rule (success path) and
    rejects an attempt to change the default rule's conditions (OperationNotPermitted)."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _get_two_subnets(ctx)

    tg1_arn = _create_target_group(ctx, vpc_id)
    tg2_arn = _create_target_group(ctx, vpc_id)

    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-mr-lb-"),
        Subnets=subnet_ids,
        Scheme="internal",
        Type="application",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg1_arn}],
    )["Listeners"][0]["ListenerArn"]

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/old"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg1_arn}],
    )["Rules"][0]["RuleArn"]

    # --- success path: ModifyRule replaces both Conditions and Actions ---
    modified = elbv2.modify_rule(
        RuleArn=rule_arn,
        Conditions=[{"Field": "path-pattern", "Values": ["/new"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg2_arn}],
    )["Rules"][0]

    assert modified["RuleArn"] == rule_arn, modified
    assert modified["Conditions"][0]["Values"] == ["/new"], modified["Conditions"]
    assert modified["Actions"][0]["TargetGroupArn"] == tg2_arn, modified["Actions"]

    # confirm persisted via a fresh read
    persisted = elbv2.describe_rules(RuleArns=[rule_arn])["Rules"][0]
    assert persisted["Conditions"][0]["Values"] == ["/new"], persisted["Conditions"]
    assert persisted["Actions"][0]["TargetGroupArn"] == tg2_arn, persisted["Actions"]

    # --- error boundary: ModifyRule cannot change the default rule's conditions ---
    default_rule_arn = None
    for rule in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]:
        if rule["IsDefault"]:
            default_rule_arn = rule["RuleArn"]
            break
    assert default_rule_arn is not None, "expected an auto-created default rule"

    code, message = _error_code(
        lambda: elbv2.modify_rule(
            RuleArn=default_rule_arn,
            Conditions=[{"Field": "path-pattern", "Values": ["/blocked"]}],
        )
    )
    assert code == "OperationNotPermitted", f"expected OperationNotPermitted, got {code}"
    assert message == f"Default rule '{default_rule_arn}' cannot be modified", message

    # effect-absent: the rejected call must not have touched the default rule
    default_after = elbv2.describe_rules(RuleArns=[default_rule_arn])["Rules"][0]
    assert default_after["Conditions"] == [], (
        f"default rule must remain condition-free after a rejected ModifyRule, got "
        f"{default_after['Conditions']}"
    )
    assert default_after["Actions"][0]["TargetGroupArn"] == tg1_arn, default_after["Actions"]



def _tags_kv():
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-mr"},
    ]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _get_two_subnets(ctx) -> tuple[str, list[str]]:

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())[:2]

    # No usable default VPC in this account/region: create our own, tagged for cleanup.
    vpc_id = ec2.create_vpc(CidrBlock="10.66.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv())
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    subnet_ids = []
    for i in range(2):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.66.{i}.0/24",
            AvailabilityZone=azs[i % len(azs)]["ZoneName"],
        )["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[subnet_id], Tags=_tags_kv())
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-mr-tg-"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        Tags=_tags_kv(),
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, arn))
    return arn


def _delete_target_group_when_free(elbv2, arn: str) -> None:
    import time as _time

    from botocore.exceptions import ClientError

    # The owning load balancer's delete is triggered by an earlier (LIFO-later-run) cleanup
    # but its listener/rule cascade completes asynchronously, so the target group can still
    # read as in-use for a few seconds. Bounded retry, not an unconditional sleep.
    deadline = _time.monotonic() + 30
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceInUse":
                raise
            if _time.monotonic() > deadline:
                raise
            _time.sleep(2)


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry inside one shared window, then fail naming the ENIs left.
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
