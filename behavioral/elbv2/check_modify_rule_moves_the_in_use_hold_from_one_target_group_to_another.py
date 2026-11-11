"""modify-rule-moves-the-in-use-hold-from-one-target-group-to-another."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-rule-moves-the-in-use-hold-from-one-target-group-to-another"
GROUP = "lifecycle"
SERVICES = ["elbv2"]
#: Bounded convergence for a load balancer transition (provisioning -> active, gone).
POLL_BUDGET_S = 40.0
#: Bounded retry for a subnet or VPC delete while the deleted ALB's interfaces are released.
NETWORK_RELEASE_S = 180.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyRule repointing a forward rule from one target group to another moves the in-use hold:
    the first group is then deletable and gone while the second refuses DeleteTargetGroup, until
    the rule is deleted and it deletes too."""
    _start_budget(ctx)
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    vpc_id, subnet_a, subnet_b = _own_network(ctx, ec2)

    lb_name = _short_name(ctx, "sim2real-albm-", 32)
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=[subnet_a, subnet_b], Type="application", Scheme="internal", Tags=_tags_kv()
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn, NETWORK_RELEASE_S))

    def _tg(label):
        arn = elbv2.create_target_group(
            Name=_short_name(ctx, f"sim2real-albm-{label}-", 32), Protocol="HTTP", Port=80, VpcId=vpc_id,
            TargetType="ip", Tags=_tags_kv(),
        )["TargetGroups"][0]["TargetGroupArn"]
        ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
        return arn

    first, second = _tg("one"), _tg("two")

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain"}}],
        Tags=_tags_kv(),
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    rule_arn = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/move/*"]}}],
        Actions=[{"Type": "forward", "TargetGroupArn": first}],
        Tags=_tags_kv(),
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_rule(RuleArn=rule_arn)))

    def _lbs(arn):
        return elbv2.describe_target_groups(TargetGroupArns=[arn])["TargetGroups"][0].get("LoadBalancerArns")

    def _expect_in_use(arn, what):
        code, http, msg = _refusal(lambda: elbv2.delete_target_group(TargetGroupArn=arn))
        in_use = f"Target group '{arn}' is currently in use by a listener or a rule"
        assert (code, msg) == ("ResourceInUse", in_use) and isinstance(http, int) and 400 <= http < 500, (
            f"DeleteTargetGroup on {what}: expected ResourceInUse/4xx {in_use!r}, got {code}/{http}: {msg!r}"
        )

    _poll_until(lambda: (_lbs(first), _lbs(second)), lambda g: g == ([lb_arn], []), interval_s=2.0, timeout_s=40.0)
    _expect_in_use(first, "the TG the rule forwards to")

    modified = elbv2.modify_rule(RuleArn=rule_arn, Actions=[{"Type": "forward", "TargetGroupArn": second}])["Rules"][0]
    assert modified.get("RuleArn") == rule_arn, "ModifyRule answered a different rule ARN"
    rule = elbv2.describe_rules(RuleArns=[rule_arn])["Rules"][0]
    forwards = [(a.get("Type"), a.get("TargetGroupArn")) for a in rule.get("Actions") or []]
    assert forwards == [("forward", second)], f"rule Actions after ModifyRule expected [('forward', second)], got {forwards!r}"
    paths = [v for c in rule.get("Conditions") or [] if c.get("Field") == "path-pattern"
             for v in (c.get("PathPatternConfig") or {}).get("Values") or []]
    assert (str(rule.get("Priority")), paths) == ("10", ["/move/*"]), (
        f"ModifyRule on actions only must keep (priority, path) ('10', ['/move/*']), got {(rule.get('Priority'), paths)!r}"
    )

    # The hold moves asynchronously: poll to the terminal (first, second) = ([], [lb]).
    _poll_until(lambda: (_lbs(first), _lbs(second)), lambda g: g == ([], [lb_arn]), interval_s=2.0, timeout_s=40.0)
    _expect_in_use(second, "the TG the rule was repointed to")
    _delete_released_tg(elbv2, first)
    for what, fn, message in (
        ("DescribeTargetGroups(TargetGroupArns)", lambda: elbv2.describe_target_groups(TargetGroupArns=[first]),
         "One or more target groups not found"),
        ("ModifyTargetGroup", lambda: elbv2.modify_target_group(TargetGroupArn=first, HealthCheckEnabled=True),
         f"Target groups '{first}' not found"),
    ):
        code, http, msg = _refusal(fn)
        assert (code, msg) == ("TargetGroupNotFound", message) and isinstance(http, int) and 400 <= http < 500, (
            f"{what} on the released, deleted TG: expected TargetGroupNotFound/4xx {message!r}, got {code}/{http}: {msg!r}"
        )

    elbv2.delete_rule(RuleArn=rule_arn)
    _delete_released_tg(elbv2, second)
    code, http, msg = _refusal(lambda: elbv2.describe_target_groups(TargetGroupArns=[second]))
    assert (code, msg) == ("TargetGroupNotFound", "One or more target groups not found") and isinstance(http, int) and 400 <= http < 500, (
        f"DescribeTargetGroups on the second deleted TG: expected TargetGroupNotFound/4xx, got {code}/{http}: {msg!r}"
    )
    elbv2.delete_listener(ListenerArn=listener_arn)
    _delete_lb_and_wait(elbv2, lb_arn, _bounded(POLL_BUDGET_S))

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


def _short_name(ctx: Any, prefix: str, max_len: int) -> str:
    return ctx.unique_name(prefix)[:max_len].rstrip("-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-albm"}]


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
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnets = []
    for i, az in enumerate(zones[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.88.{i + 1}.0/24",
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
