"""alb-listener-target-group-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alb-listener-target-group-lifecycle"
GROUP = "lifecycle"
SERVICES = ["elbv2"]
#: Bounded convergence for a load balancer transition (provisioning -> active, gone).
POLL_BUDGET_S = 180.0
#: Bounded retry for a subnet or VPC delete while the deleted ALB's interfaces are released.
NETWORK_RELEASE_S = 180.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLoadBalancer (own VPC, 2 AZs) -> CreateTargetGroup (ip) -> CreateListener (fixed-response)
    -> independent reads -> CreateRule forwarding to the TG, which then refuses DeleteTargetGroup ->
    delete rule, listener, TG, LB, each proven gone."""
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    vpc_id, subnet_a, subnet_b = _own_network(ctx, ec2)
    arn_base = f"arn:{_partition(ctx)}:elasticloadbalancing:{ctx.region}:{ctx.account}"

    # --- Load balancer ---
    lb_name = _short_name(ctx, "sim2real-albl-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal", Tags=_tags_kv()
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
    lb_prefix = f"{arn_base}:loadbalancer/app/{lb_name}/"
    assert lb_arn.startswith(lb_prefix) and len(lb_arn) > len(lb_prefix), (
        f"expected the LB ARN to be {lb_prefix!r}<id>, got {lb_arn!r}"
    )
    lb_id = lb_arn[len(lb_prefix):]

    # --- Target group (ip, nothing registered) ---
    tg_name = _short_name(ctx, "sim2real-albl-tg-", 32)
    tg_arn = elbv2.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip", Tags=_tags_kv()
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn)))
    tg_prefix = f"{arn_base}:targetgroup/{tg_name}/"
    assert tg_arn.startswith(tg_prefix) and len(tg_arn) > len(tg_prefix), (
        f"expected the TG ARN to be {tg_prefix!r}<id>, got {tg_arn!r}"
    )

    # Terminal state only: the LB is active before the listener reads are graded.
    lb = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda d: d.get("State", {}).get("Code") == "active",
        interval_s=10.0,
    )

    # --- Listener (HTTP:80, fixed-response default action) ---
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain"}}],
        Tags=_tags_kv(),
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))
    li_prefix = f"{arn_base}:listener/app/{lb_name}/{lb_id}/"
    assert listener_arn.startswith(li_prefix) and len(listener_arn) > len(li_prefix), (
        f"expected the listener ARN to be {li_prefix!r}<id>, got {listener_arn!r}"
    )

    # --- Independent reads of each resource ---
    got = (lb.get("LoadBalancerName"), lb.get("Type"), lb.get("Scheme"), lb.get("VpcId"))
    want = (lb_name, "application", "internal", vpc_id)
    assert got == want, f"DescribeLoadBalancers (name, type, scheme, vpc) expected {want!r}, got {got!r}"
    lb_subnets = {az.get("SubnetId") for az in lb.get("AvailabilityZones", [])}
    assert lb_subnets == {subnet_a, subnet_b}, (
        f"DescribeLoadBalancers AvailabilityZones subnets expected {sorted({subnet_a, subnet_b})!r}, "
        f"got {sorted(s for s in lb_subnets if s)!r}"
    )

    tgs = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"]
    assert [t.get("TargetGroupArn") for t in tgs] == [tg_arn], (
        f"DescribeTargetGroups(TargetGroupArns=[tg]) expected exactly [{tg_arn!r}], got {tgs!r}"
    )
    tg = tgs[0]
    got = (tg.get("TargetGroupName"), tg.get("TargetType"), tg.get("Protocol"), tg.get("Port"), tg.get("VpcId"))
    want = (tg_name, "ip", "HTTP", 80, vpc_id)
    assert got == want, f"DescribeTargetGroups (name, type, protocol, port, vpc) expected {want!r}, got {got!r}"
    assert tg.get("LoadBalancerArns") == [], (
        f"a TG no listener forwards to expected LoadBalancerArns [], got {tg.get('LoadBalancerArns')!r}"
    )
    health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert health == [], f"DescribeTargetHealth on a TG with no targets expected [], got {health!r}"

    lis = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"]
    assert [x.get("ListenerArn") for x in lis] == [listener_arn], (
        f"DescribeListeners(ListenerArns=[l]) expected exactly [{listener_arn!r}], got {lis!r}"
    )
    li = lis[0]
    got = (li.get("LoadBalancerArn"), li.get("Protocol"), li.get("Port"))
    want = (lb_arn, "HTTP", 80)
    assert got == want, f"DescribeListeners (lb, protocol, port) expected {want!r}, got {got!r}"
    actions = li.get("DefaultActions") or []
    got = [(a.get("Type"), (a.get("FixedResponseConfig") or {}).get("StatusCode"),
            (a.get("FixedResponseConfig") or {}).get("ContentType")) for a in actions]
    want = [("fixed-response", "200", "text/plain")]
    assert got == want, f"listener DefaultActions (type, status, content type) expected {want!r}, got {got!r}"
    on_lb = [x["ListenerArn"] for x in elbv2.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]]
    assert on_lb == [listener_arn], f"DescribeListeners(LoadBalancerArn) expected [{listener_arn!r}], got {on_lb!r}"

    # --- Forward rule: path-pattern -> the target group ---
    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/sim2real/*"]}}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(),
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_rule(RuleArn=rule_arn)))
    rules = elbv2.describe_rules(RuleArns=[rule_arn])["Rules"]
    assert [r.get("RuleArn") for r in rules] == [rule_arn], (
        f"DescribeRules(RuleArns=[r]) expected exactly [{rule_arn!r}], got {rules!r}"
    )
    rule = rules[0]
    assert str(rule.get("Priority")) == "10", f"rule Priority expected '10', got {rule.get('Priority')!r}"
    paths = [v for c in rule.get("Conditions") or [] if c.get("Field") == "path-pattern"
             for v in (c.get("PathPatternConfig") or {}).get("Values") or c.get("Values") or []]
    assert paths == ["/sim2real/*"], f"rule path-pattern values expected ['/sim2real/*'], got {paths!r}"
    forwards = [(a.get("Type"), a.get("TargetGroupArn")) for a in rule.get("Actions") or []]
    assert forwards == [("forward", tg_arn)], f"rule Actions (type, tg) expected [('forward', {tg_arn!r})], got {forwards!r}"
    on_listener = [r.get("RuleArn") for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]]
    assert rule_arn in on_listener, f"DescribeRules(ListenerArn) does not list the rule {rule_arn!r}: {on_listener!r}"

    # While the rule forwards to it, the target group cannot be deleted and stays describable.
    code, http, msg = _refusal(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    in_use = f"Target group '{tg_arn}' is currently in use by a listener or a rule"
    assert (code, msg) == ("ResourceInUse", in_use) and isinstance(http, int) and 400 <= http < 500, (
        f"DeleteTargetGroup on a TG a rule forwards to: expected ResourceInUse/4xx {in_use!r}, "
        f"got {code}/{http}: {msg!r}"
    )
    still = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"]
    assert [t.get("TargetGroupArn") for t in still] == [tg_arn], (
        f"the refused DeleteTargetGroup must leave the TG describable, got {still!r}"
    )

    # --- Teardown in dependency order ---
    elbv2.delete_rule(RuleArn=rule_arn)
    code, http, msg = _refusal(lambda: elbv2.describe_rules(RuleArns=[rule_arn]))
    assert (code, msg) == ("RuleNotFound", "One or more rules not found") and isinstance(http, int) and 400 <= http < 500, (
        f"DescribeRules on the deleted rule: expected RuleNotFound/4xx 'One or more rules not found', "
        f"got {code}/{http}: {msg!r}"
    )

    elbv2.delete_listener(ListenerArn=listener_arn)
    code, http, msg = _refusal(lambda: elbv2.describe_listeners(ListenerArns=[listener_arn]))
    assert (code, msg) == ("ListenerNotFound", "One or more listeners not found") and isinstance(http, int) and 400 <= http < 500, (
        f"DescribeListeners on the deleted listener: expected ListenerNotFound/4xx 'One or more listeners "
        f"not found', got {code}/{http}: {msg!r}"
    )

    # Target group gone: by ARN, from a listing filtered to its name, and refusing mutation.
    elbv2.delete_target_group(TargetGroupArn=tg_arn)
    for what, fn, message in (
        ("DescribeTargetGroups(TargetGroupArns)", lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]),
         "One or more target groups not found"),
        ("DescribeTargetGroups(Names)", lambda: elbv2.describe_target_groups(Names=[tg_name]),
         "One or more target groups not found"),
        ("ModifyTargetGroup", lambda: elbv2.modify_target_group(TargetGroupArn=tg_arn, HealthCheckEnabled=True),
         f"Target groups '{tg_arn}' not found"),
    ):
        code, http, msg = _refusal(fn)
        assert (code, msg) == ("TargetGroupNotFound", message) and isinstance(http, int) and 400 <= http < 500, (
            f"{what} on the deleted target group: expected TargetGroupNotFound/4xx {message!r}, "
            f"got {code}/{http}: {msg!r}"
        )

    # Load balancer gone: the delete is asynchronous, so poll the by-ARN read to its terminal
    # not-found answer; then the name-filtered listing and a mutation on the dead ARN.
    elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    deadline = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LoadBalancerNotFound":
                raise
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer {lb_arn} still readable {POLL_BUDGET_S}s after delete")
        time.sleep(3.0)
    for what, fn, message in (
        ("DescribeLoadBalancers(LoadBalancerArns)", lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn]),
         "One or more load balancers not found"),
        ("DescribeLoadBalancers(Names)", lambda: elbv2.describe_load_balancers(Names=[lb_name]),
         f"Load balancers '[{lb_name}]' not found"),
        ("AddTags", lambda: elbv2.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": "after", "Value": "delete"}]),
         "One or more load balancers not found"),
    ):
        code, http, msg = _refusal(fn)
        assert (code, msg) == ("LoadBalancerNotFound", message) and isinstance(http, int) and 400 <= http < 500, (
            f"{what} on the deleted load balancer: expected LoadBalancerNotFound/4xx {message!r}, "
            f"got {code}/{http}: {msg!r}"
        )


def _refusal(fn):
    """(code, HTTP status, message) of the ClientError ``fn`` raises; raises if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"the call should have been refused, but it succeeded: {result!r}")


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
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"load balancer {lb_arn} was not removed within {timeout_s}s")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *,
                timeout_s: float = POLL_BUDGET_S, interval_s: float) -> Any:
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
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-albl"}]


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
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnets = []
    for i, az in enumerate(zones[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.80.{i + 1}.0/24",
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
