"""listener-rule-priority-precedence-data-plane."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-rule-priority-precedence-data-plane"
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects — a 3xx is an assertable outcome, not a hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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


def _http(ctx, url, *, method="GET", headers=None, timeout=20):
    """(status, header_message, body_text). 4xx/5xx are returned, never raised."""
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _default_vpc_and_subnets(ctx, num_subnets=2):
    """Default-VPC subnets, one per AZ. An ALB needs >= 2 AZs and public subnets."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this region to place an internet-facing ALB in")
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


def _open_http_sg(ctx, vpc_id, port=80):
    """SG allowing inbound `port` so the check host can drive the ALB data plane."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # A deleting load balancer's ENIs hold the group briefly: retry only DependencyViolation.
        deadline = time.monotonic() + 180
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()],
        }],
    )
    return sg_id


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Create an LB and register its (waited) teardown AT CREATION.

    ELBv2 load balancers are billable, so teardown is registered before the ARN is
    ever used. Cleanups run LIFO, so creating LB -> target group -> listener yields
    the required reverse-dependency teardown: listener, target group, load balancer.
    """
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(
        Name=name, Subnets=subnet_ids, Type="application",
        Scheme="internal", Tags=list(_TAGS),
    )
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


def _create_rule(ctx, listener_arn, priority, conditions, actions):
    elb = ctx.client("elbv2")
    rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=conditions, Actions=actions, Tags=list(_TAGS),
    ))["Rules"][0]
    arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=arn))
    return rule


def _fixed(body, status="200"):
    return [{
        "Type": "fixed-response",
        "FixedResponseConfig": {
            "StatusCode": status, "ContentType": "text/plain", "MessageBody": body,
        },
    }]


def _wait_for_body(ctx, url, expected, *, headers=None, timeout_s=300, description=""):
    """Poll the ALB data plane until it serves `expected`.

    Absorbs DNS propagation and listener/rule convergence, then asserts the exact
    body — so a wrong-rule answer still fails instead of being retried away.
    """
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body[:60]}")
        return (status, body)

    got = _poll_until(
        probe, lambda r: r is not None and r[1].strip() == expected,
        timeout_s=timeout_s, interval_s=5,
        description=description or f"GET {url} serving {expected!r} (observed: {seen[-6:]})",
    )
    assert got[0] == 200, f"expected HTTP 200 from {url}, got {got[0]}"
    return got
# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """When two listener rules match the same request, the lowest-numbered one serves it over HTTP,
    and SetRulePriorities flips which rule answers."""
    elb = ctx.client("elbv2")
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    sg_id = _open_http_sg(ctx, vpc_id, 80)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=_fixed("DEFAULT-RULE"),
    )
    la = listener["ListenerArn"]

    # Both rules match /shared/* . Priority 10 must win over priority 20.
    rule_hi = _create_rule(
        ctx, la, 10,
        [{"Field": "path-pattern", "Values": ["/shared/*"]}],
        _fixed("PRIORITY-10"),
    )
    rule_lo = _create_rule(
        ctx, la, 20,
        [{"Field": "path-pattern", "Values": ["/shared/*"]}],
        _fixed("PRIORITY-20"),
    )
    assert str(rule_hi["Priority"]) == "10", rule_hi["Priority"]
    assert str(rule_lo["Priority"]) == "20", rule_lo["Priority"]

    base = f"http://{lb['DNSName']}"

    # 1. The lower priority number wins even though both rules match.
    _wait_for_body(ctx,
        f"{base}/shared/thing", "PRIORITY-10",
        description="priority-10 rule winning over the equally-matching priority-20 rule",
    )

    # 2. A request matching NO rule falls through to the listener default action.
    _wait_for_body(ctx,
        f"{base}/not-shared", "DEFAULT-RULE",
        description="unmatched request falling through to the listener default action",
    )

    # 3. Reorder: the formerly-losing rule becomes the lowest priority and must win.
    _retry_throttled(lambda: elb.set_rule_priorities(RulePriorities=[
        {"RuleArn": rule_hi["RuleArn"], "Priority": 30},
        {"RuleArn": rule_lo["RuleArn"], "Priority": 5},
    ]))
    described = {
        r["RuleArn"]: str(r["Priority"])
        for r in elb.describe_rules(ListenerArn=la)["Rules"]
    }
    assert described.get(rule_lo["RuleArn"]) == "5", described
    assert described.get(rule_hi["RuleArn"]) == "30", described

    _wait_for_body(ctx,
        f"{base}/shared/thing", "PRIORITY-20",
        description="reordered rule (now priority 5) taking over the routing decision",
    )

    # 4. The default rule is untouched by the reorder (control).
    _wait_for_body(ctx,
        f"{base}/not-shared", "DEFAULT-RULE",
        description="default action still serving unmatched requests after the reorder",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
