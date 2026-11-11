"""set-rule-priorities-ignores-other-listener."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-rule-priorities-ignores-other-listener"
GROUP = 'rule-lifecycle'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRulePriorities onto a priority held by a rule on a different listener succeeds: priority
    uniqueness is per listener, so the other rule is untouched and both report the same priority."""

    _net_cache = {}
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _retry_throttled(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        last_exc = None
        for attempt in range(attempts):
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    raise
                last_exc = exc
                time.sleep(delays[min(attempt, len(delays) - 1)])
        raise last_exc

    def _setup_network(num_subnets=2):
        if _net_cache:
            return _net_cache["net"]
        # The check mints its own VPC rather than adopting the account's default one: an
        # internal load balancer needs only two subnets in two AZs, no internet gateway.
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }])["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az,
                                    TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
                                    )["Subnet"]["SubnetId"]
            subnet_ids.append(sid)
            ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        _net_cache["net"] = (vpc_id, subnet_ids)
        return _net_cache["net"]

    def _create_load_balancer(name=None, subnet_ids=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-lb-"))
        if subnet_ids is None:
            _, subnet_ids = _setup_network()
        params = dict(
            Name=name,
            Subnets=subnet_ids,
            Type=kwargs.pop("Type", "application"),
            Scheme=kwargs.pop("Scheme", "internal"),
            Tags=kwargs.pop("Tags", _tags_kv()),
        )
        params.update(kwargs)
        lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
        arn = lb["LoadBalancerArn"]
        ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
        return lb

    def _create_target_group(name=None, vpc_id=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-tg-"))
        params = dict(Name=name, Protocol="HTTP", Port=80, TargetType="ip")
        params.update(kwargs)
        if params.get("TargetType") != "lambda":
            if vpc_id is None:
                vpc_id, _ = _setup_network()
            params.setdefault("VpcId", vpc_id)
        elif vpc_id is not None:
            params["VpcId"] = vpc_id
        params.setdefault("Tags", _tags_kv())
        tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
        arn = tg["TargetGroupArn"]
        ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=arn))
        return tg

    def _create_listener(load_balancer_arn, **kwargs):
        params = dict(LoadBalancerArn=load_balancer_arn, Protocol="HTTP", Port=80)
        params.update(kwargs)
        listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
        arn = listener["ListenerArn"]
        ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
        return listener

    def _create_rule(listener_arn, priority, conditions, actions):
        rule = _retry_throttled(lambda: elb.create_rule(
            ListenerArn=listener_arn, Priority=priority, Conditions=conditions, Actions=actions,
        ))["Rules"][0]
        arn = rule["RuleArn"]
        ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=arn))
        return rule

    # Listener A: the rule we are going to move.
    lb_a = _create_load_balancer()
    tg_a = _create_target_group()
    listener_a = _create_listener(
        lb_a["LoadBalancerArn"],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_a["TargetGroupArn"]}],
    )
    rule_a = _create_rule(
        listener_a["ListenerArn"],
        priority=10,
        conditions=[{"Field": "path-pattern", "Values": ["/a/*"]}],
        actions=[{"Type": "forward", "TargetGroupArn": tg_a["TargetGroupArn"]}],
    )

    # Listener B: a completely separate load balancer (its own target group too -- a target
    # group cannot be associated with more than one load balancer), with its own rule already
    # sitting at priority 100 -- the number listener A's rule is about to be moved to.
    lb_b = _create_load_balancer()
    tg_b = _create_target_group()
    listener_b = _create_listener(
        lb_b["LoadBalancerArn"],
        Port=81,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_b["TargetGroupArn"]}],
    )
    rule_b = _create_rule(
        listener_b["ListenerArn"],
        priority=100,
        conditions=[{"Field": "path-pattern", "Values": ["/b/*"]}],
        actions=[{"Type": "forward", "TargetGroupArn": tg_b["TargetGroupArn"]}],
    )

    set_resp = _retry_throttled(
        lambda: elb.set_rule_priorities(
            RulePriorities=[{"RuleArn": rule_a["RuleArn"], "Priority": 100}]
        )
    )["Rules"]
    assert [r["RuleArn"] for r in set_resp] == [rule_a["RuleArn"]], (
        f"expected SetRulePriorities to report only the named rule, got {set_resp}"
    )
    assert str(set_resp[0]["Priority"]) == "100", (
        f"expected the moved rule's own response to carry priority 100, got {set_resp[0]['Priority']!r}"
    )

    rules_a = elb.describe_rules(ListenerArn=listener_a["ListenerArn"])["Rules"]
    by_arn_a = {r["RuleArn"]: r for r in rules_a if not r.get("IsDefault")}
    assert str(by_arn_a[rule_a["RuleArn"]]["Priority"]) == "100", (
        f"expected moved rule at priority 100 on listener A, got {by_arn_a[rule_a['RuleArn']]['Priority']!r}"
    )

    rules_b = elb.describe_rules(ListenerArn=listener_b["ListenerArn"])["Rules"]
    by_arn_b = {r["RuleArn"]: r for r in rules_b if not r.get("IsDefault")}
    assert str(by_arn_b[rule_b["RuleArn"]]["Priority"]) == "100", (
        "expected listener B's rule, which SetRulePriorities was never told about, to keep "
        f"priority 100 unperturbed, got {by_arn_b[rule_b['RuleArn']]['Priority']!r}"
    )


# Subnet / security group / VPC deletes fail with DependencyViolation while AWS-managed ENIs of an
# asynchronously deleted resource (e.g. a load balancer) remain, so wait (bounded) for them to go,
# retry inside one shared window, and finally raise naming the ENIs still attached.
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
