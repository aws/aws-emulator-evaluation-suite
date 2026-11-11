"""weighted-forward-rule-holds-both-target-groups-in-use-until-it-is-deleted."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "weighted-forward-rule-holds-both-target-groups-in-use-until-it-is-deleted"
GROUP = "lifecycle"
SERVICES = ["elbv2"]
#: Bounded convergence for a load balancer transition (provisioning -> active, gone).
POLL_BUDGET_S = 40.0
#: Bounded retry for a subnet or VPC delete while the deleted ALB's interfaces are released.
NETWORK_RELEASE_S = 180.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A host-header rule forwarding 70/30 to two instance target groups reads back both weights
    and holds BOTH groups in use: each refuses DeleteTargetGroup naming its own ARN and lists the
    load balancer; once the rule is deleted both groups detach and delete, each proven gone."""
    _start_budget(ctx)
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    vpc_id, subnet_a, subnet_b = _own_network(ctx, ec2)
    arn_base = f"arn:{_partition(ctx)}:elasticloadbalancing:{ctx.region}:{ctx.account}"

    lb_name = _short_name(ctx, "sim2real-albw-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal", Tags=_tags_kv()
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn, NETWORK_RELEASE_S))

    tgs = {}
    for port in (8080, 8081):
        tg_name = _short_name(ctx, f"sim2real-albw-{port}-", 32)
        arn = elbv2.create_target_group(
            Name=tg_name, Protocol="HTTP", Port=port, VpcId=vpc_id, TargetType="instance", Tags=_tags_kv()
        )["TargetGroups"][0]["TargetGroupArn"]
        ctx.on_cleanup(lambda a=arn: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=a)))
        prefix = f"{arn_base}:targetgroup/{tg_name}/"
        assert arn.startswith(prefix) and len(arn) > len(prefix), f"expected the TG ARN to be {prefix!r}<id>, got {arn!r}"
        tgs[port] = arn
    heavy, light = tgs[8080], tgs[8081]

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=8000,
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "404", "ContentType": "text/plain"}}],
        Tags=_tags_kv(),
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    for arn in (heavy, light):
        tg = elbv2.describe_target_groups(TargetGroupArns=[arn])["TargetGroups"][0]
        assert tg.get("LoadBalancerArns") == [], f"a TG nothing forwards to expected LoadBalancerArns [], got {tg.get('LoadBalancerArns')!r}"

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=7,
        Conditions=[{"Field": "host-header", "HostHeaderConfig": {"Values": ["app.example.com"]}}],
        Actions=[{"Type": "forward", "ForwardConfig": {"TargetGroups": [
            {"TargetGroupArn": heavy, "Weight": 70}, {"TargetGroupArn": light, "Weight": 30}]}}],
        Tags=_tags_kv(),
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_rule(RuleArn=rule_arn)))

    rule = elbv2.describe_rules(RuleArns=[rule_arn])["Rules"][0]
    hosts = [v for c in rule.get("Conditions") or [] if c.get("Field") == "host-header"
             for v in (c.get("HostHeaderConfig") or {}).get("Values") or []]
    got = (str(rule.get("Priority")), hosts)
    assert got == ("7", ["app.example.com"]), f"rule (priority, host-header values) expected ('7', ['app.example.com']), got {got!r}"
    actions = rule.get("Actions") or []
    assert [a.get("Type") for a in actions] == ["forward"], f"rule action types expected ['forward'], got {actions!r}"
    weights = {t.get("TargetGroupArn"): t.get("Weight")
               for t in (actions[0].get("ForwardConfig") or {}).get("TargetGroups") or []}
    assert weights == {heavy: 70, light: 30}, f"rule forward weights expected {{8080 TG: 70, 8081 TG: 30}}, got {weights!r}"

    for arn in (heavy, light):
        _poll_until(
            lambda a=arn: elbv2.describe_target_groups(TargetGroupArns=[a])["TargetGroups"][0].get("LoadBalancerArns"),
            lambda lbs: lbs == [lb_arn], timeout_s=40.0, interval_s=2.0,
        )
        code, http, msg = _refusal(lambda a=arn: elbv2.delete_target_group(TargetGroupArn=a))
        in_use = f"Target group '{arn}' is currently in use by a listener or a rule"
        assert (code, msg) == ("ResourceInUse", in_use) and isinstance(http, int) and 400 <= http < 500, (
            f"DeleteTargetGroup on a weighted-forward TG: expected ResourceInUse/4xx {in_use!r}, got {code}/{http}: {msg!r}"
        )

    elbv2.delete_rule(RuleArn=rule_arn)
    code, http, msg = _refusal(lambda: elbv2.describe_rules(RuleArns=[rule_arn]))
    assert (code, msg) == ("RuleNotFound", "One or more rules not found") and isinstance(http, int) and 400 <= http < 500, (
        f"DescribeRules on the deleted rule: expected RuleNotFound/4xx, got {code}/{http}: {msg!r}"
    )

    for arn in (heavy, light):
        # With the rule deleted, the TG is released (LoadBalancerArns []) and deletes.
        _delete_released_tg(elbv2, arn)
        code, http, msg = _refusal(lambda a=arn: elbv2.describe_target_groups(TargetGroupArns=[a]))
        assert (code, msg) == ("TargetGroupNotFound", "One or more target groups not found") and isinstance(http, int) and 400 <= http < 500, (
            f"DescribeTargetGroups on the deleted TG: expected TargetGroupNotFound/4xx, got {code}/{http}: {msg!r}"
        )

    elbv2.delete_listener(ListenerArn=listener_arn)
    _delete_lb_and_wait(elbv2, lb_arn, _bounded(POLL_BUDGET_S))
    code, http, msg = _refusal(lambda: elbv2.describe_load_balancers(Names=[lb_name]))
    assert (code, msg) == ("LoadBalancerNotFound", f"Load balancers '[{lb_name}]' not found") and isinstance(http, int) and 400 <= http < 500, (
        f"DescribeLoadBalancers(Names) on the deleted LB: expected LoadBalancerNotFound/4xx, got {code}/{http}: {msg!r}"
    )

#: The runner's deadline for this check (monotonic clock), set as run() starts.
_RUN_END: dict = {}


def _bounded(timeout_s: float) -> float:
    """``timeout_s`` cut to the time the runner leaves this check, so a wait fails with its own
    last observation rather than the runner's timeout."""
    end = _RUN_END.get("t")
    return timeout_s if end is None else max(1.0, min(timeout_s, end - time.monotonic() - 3.0))


def _start_budget(ctx) -> None:
    left = ctx.time_left()
    _RUN_END["t"] = None if left is None else time.monotonic() + left



def _refusal(fn):
    """(code, HTTP status, message) of the ClientError ``fn`` raises; raises if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"the call should have been refused, but it succeeded: {result!r}")


def _delete_released_tg(elbv2, arn: str, timeout_s: float = 40.0) -> None:
    """Wait (bounded) until no load balancer holds the TG, then delete it; AWS releases the hold
    asynchronously, so ResourceInUse is retried within the same window."""
    timeout_s = _bounded(timeout_s)
    _poll_until(
        lambda: elbv2.describe_target_groups(TargetGroupArns=[arn])["TargetGroups"][0].get("LoadBalancerArns"),
        lambda lbs: lbs == [], timeout_s=timeout_s, interval_s=2.0,
    )
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response.get("Error", {}).get("Code", ""):
            raise


def _delete_lb_and_wait(elbv2, lb_arn: str, timeout_s: float = POLL_BUDGET_S) -> None:
    """Teardown: delete the LB unless already gone, then wait (bounded) until it reads not-found."""
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "LoadBalancerNotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0].get("State")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"load balancer {lb_arn} was not removed within {timeout_s}s (last state {last!r})")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                timeout_s: float = POLL_BUDGET_S, interval_s: float) -> Any:
    timeout_s = _bounded(timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    return ctx.unique_name(prefix)[:max_len].rstrip("-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-albw"}]


def _own_network(ctx, ec2) -> tuple[str, str, str]:
    """The check's own VPC with one subnet in each of two Availability Zones; teardown retries
    the deletes while the deleted ALB's network interfaces are released."""
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
        if z.get("ZoneType", "availability-zone") == "availability-zone"
    )
    assert len(zones) >= 2, f"region {ctx.region} reports fewer than two available AZs: {zones!r}"
    tag_spec = [{"Key": "sim2real", "Value": CHECK}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.87.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnets = []
    for i, az in enumerate(zones[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.87.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _delete_subnet_after_enis(ec2, s))
        subnets.append(subnet_id)
    return vpc_id, subnets[0], subnets[1]


def _delete_subnet_after_enis(ec2, subnet_id: str, timeout_s: float = NETWORK_RELEASE_S) -> None:
    """Teardown: wait (bounded) for the deleted ALB's network interfaces to leave, then delete."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}])["NetworkInterfaces"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "").endswith(".NotFound"):
                return
            raise
        if not enis:
            break
        time.sleep(10)
    _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id))


def _retry_dependency(fn: Callable[[], Any], timeout_s: float = NETWORK_RELEASE_S) -> None:
    """Teardown: retry ``fn`` through DependencyViolation (bounded); not-found means already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
