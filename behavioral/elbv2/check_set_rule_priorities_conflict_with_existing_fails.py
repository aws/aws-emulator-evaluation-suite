"""set-rule-priorities-conflict-with-existing-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-rule-priorities-conflict-with-existing-fails"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetRulePriorities moving a rule onto a priority another rule still holds must fail
    (overly-permissive check); freeing that priority makes the identical call succeed."""

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

    def _rejects(fn):
        """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
        emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
        delays = [3, 6, 12, 24, 30]
        for attempt in range(5):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                code = err.get("Code")
                if code in _THROTTLE_CODES:
                    time.sleep(delays[attempt])
                    continue
                return code, err.get("Message")
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
        raise AssertionError("exhausted retries against throttling")

    def _ignore_not_found(fn):
        try:
            fn()
        except ClientError as exc:
            if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
                raise

    def _setup_network(num_subnets=2):
        if _net_cache:
            return _net_cache["net"]
        default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if default_vpcs:
            vpc_id = default_vpcs[0]["VpcId"]
            subnets = ec2.describe_subnets(Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ])["Subnets"]
            per_az = {}
            for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
                per_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
            subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
            if len(subnet_ids) >= min(num_subnets, 2):
                _net_cache["net"] = (vpc_id, subnet_ids)
                return _net_cache["net"]
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
        try:
            ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}])
        except Exception:
            pass
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
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
        ctx.on_cleanup(lambda: _ignore_not_found(lambda: elb.delete_rule(RuleArn=arn)))
        return rule

    def _priorities(listener_arn):
        return {
            r["RuleArn"]: int(r["Priority"])
            for r in elb.describe_rules(ListenerArn=listener_arn)["Rules"]
            if not r.get("IsDefault")
        }

    lb = _create_load_balancer()
    tg = _create_target_group()
    listener = _create_listener(
        lb["LoadBalancerArn"],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )
    rule_a = _create_rule(
        listener["ListenerArn"],
        priority=20,
        conditions=[{"Field": "path-pattern", "Values": ["/a/*"]}],
        actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )
    rule_b = _create_rule(
        listener["ListenerArn"],
        priority=21,
        conditions=[{"Field": "path-pattern", "Values": ["/b/*"]}],
        actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )

    # Positive control: SetRulePriorities on an unheld priority succeeds.
    _retry_throttled(lambda: elb.set_rule_priorities(
        RulePriorities=[{"RuleArn": rule_a["RuleArn"], "Priority": 22}]
    ))
    priorities = _priorities(listener["ListenerArn"])
    assert priorities[rule_a["RuleArn"]] == 22, (
        f"positive control failed: expected rule_a moved to 22, got {priorities}"
    )

    # Break: priority 21 is still held by rule_b, so moving rule_a there is a genuine conflict.
    code, message = _rejects(lambda: elb.set_rule_priorities(
        RulePriorities=[{"RuleArn": rule_a["RuleArn"], "Priority": 21}]
    ))
    assert code == "PriorityInUse", (
        f"expected priority-in-use error, got {code}"
    )
    expected_message = "One or more priorities not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected call must not have moved rule_a off its control position.
    priorities = _priorities(listener["ListenerArn"])
    assert priorities[rule_a["RuleArn"]] == 22, (
        f"priority changed despite a rejected SetRulePriorities call: {priorities}"
    )

    # Restore: free priority 21 by removing the rule holding it, then the identical call
    # must succeed against real AWS.
    _retry_throttled(lambda: elb.delete_rule(RuleArn=rule_b["RuleArn"]))
    _retry_throttled(lambda: elb.set_rule_priorities(
        RulePriorities=[{"RuleArn": rule_a["RuleArn"], "Priority": 21}]
    ))
    priorities = _priorities(listener["ListenerArn"])
    assert priorities[rule_a["RuleArn"]] == 21, (
        f"expected rule_a to move onto freed priority 21, got {priorities}"
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
