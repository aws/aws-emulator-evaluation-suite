"""create-rule-malformed-regex-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rule-malformed-regex-value-rejected"
GROUP = 'data-plane'
SERVICES = ['elbv2']

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


def _retry_throttled(fn, attempts=5):
    delays = [3, 6, 12, 24, 30]
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(delays[min(i, len(delays) - 1)])
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _shared_vpc_and_subnets(ctx, num_subnets=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this region to place an ALB in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    per_az = {}
    for sub in sorted(subnets, key=lambda s: s["SubnetId"]):
        per_az.setdefault(sub["AvailabilityZone"], sub["SubnetId"])
    subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
    if len(subnet_ids) < num_subnets:
        raise AssertionError(
            f"shared network VPC {vpc_id} exposes {len(subnet_ids)} AZ subnets, need {num_subnets}"
        )
    return vpc_id, subnet_ids


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(Name=name, Subnets=subnet_ids, Type="application", Scheme="internal", Tags=list(_TAGS))
    params.update(kwargs)
    lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=10,
        description="load balancer reaching a terminal provisioning state",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return listener


def _fixed(body, status="200"):
    return [{"Type": "fixed-response", "FixedResponseConfig": {
        "StatusCode": status, "ContentType": "text/plain", "MessageBody": body}}]
# ===== end helpers =====


_BAD_REGEX = r"^/bad/(unclosed"
_GOOD_REGEX = r"^/ok/[a-z]+$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRule accepts a syntactically valid RegexValues pattern and refuses one with
    unbalanced regex syntax, leaving no rule behind for the refused priority.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-condition-types.html
    """
    elb = ctx.client("elbv2")
    vpc_id, subnet_ids = _shared_vpc_and_subnets(ctx)
    lb = _create_load_balancer(ctx, subnet_ids)
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP", DefaultActions=_fixed("DEFAULT"),
    )
    la = listener["ListenerArn"]

    # POSITIVE CONTROL: a syntactically valid regex is accepted.
    good = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=la, Priority=5,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"RegexValues": [_GOOD_REGEX]}}],
        Actions=_fixed("OK"), Tags=list(_TAGS),
    ))["Rules"][0]
    good_arn = good["RuleArn"]

    def _drop_good():
        try:
            elb.delete_rule(RuleArn=good_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RuleNotFound":
                raise

    ctx.on_cleanup(_drop_good)

    # BREAK: the same shape with unbalanced regex syntax is refused.
    code, message = _error(lambda: elb.create_rule(
        ListenerArn=la, Priority=6,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"RegexValues": [_BAD_REGEX]}}],
        Actions=_fixed("BAD"), Tags=list(_TAGS),
    ))
    assert code == "ValidationError", (
        f"malformed RegexValues {_BAD_REGEX!r} returned code {code!r} (message {message!r}), "
        f"expected ValidationError"
    )
    expected_message = "One or more provided condition regex values are not valid"
    assert message == expected_message, (
        f"malformed RegexValues {_BAD_REGEX!r} returned message {message!r}, "
        f"expected {expected_message!r}"
    )

    # EFFECT ABSENT: the refused priority never produced a rule, while the valid one is present.
    rules = {str(r["Priority"]): r for r in elb.describe_rules(ListenerArn=la)["Rules"]}
    assert "6" not in rules, f"a rule exists at refused priority 6: {rules.get('6')!r}"
    assert "5" in rules, f"the positive control's rule at priority 5 is missing: {sorted(rules)!r}"
    assert rules["5"]["Conditions"][0]["PathPatternConfig"]["RegexValues"] == [_GOOD_REGEX], \
        rules["5"]["Conditions"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
