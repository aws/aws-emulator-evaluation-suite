"""listener-rule-condition-type-matrix-routing."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-rule-condition-type-matrix-routing"
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
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _default_vpc_and_subnets(ctx, num_subnets=2):
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
    """Billable resource: waited teardown is registered AT CREATION (LIFO => last)."""
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


def _wait_for_body(ctx, url, expected, *, headers=None, method="GET", timeout_s=300, description=""):
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url, method=method, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body[:60]}")
        return (status, body)

    got = _poll_until(
        probe, lambda r: r is not None and r[1].strip() == expected,
        timeout_s=timeout_s, interval_s=5,
        description=description or f"{method} {url} serving {expected!r} (observed: {seen[-6:]})",
    )
    assert got[0] == 200, f"expected HTTP 200 from {url}, got {got[0]}"
    return got


def _assert_body(ctx, url, expected, *, headers=None, method="GET"):
    """One-shot exact-body assertion (used once the data plane is known warm)."""
    status, _hdrs, body = _http(ctx, url, method=method, headers=headers)
    assert status == 200, f"{method} {url} headers={headers}: HTTP {status}, body={body[:200]!r}"
    assert body.strip() == expected, (
        f"{method} {url} headers={headers}: routed to {body.strip()!r}, expected {expected!r}"
    )
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Each ALB rule condition type (path-pattern, host-header, http-header, http-request-method,
    query-string) routes its request to its own rule over HTTP, and a near-miss request falls
    through to the default action."""
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

    host_value = "sim2real-behav-host.example.com"
    _create_rule(ctx, la, 10, [{
        "Field": "host-header",
        "HostHeaderConfig": {"Values": [host_value]},
    }], _fixed("BY-HOST-HEADER"))
    _create_rule(ctx, la, 20, [{
        "Field": "http-header",
        "HttpHeaderConfig": {"HttpHeaderName": "X-Sim2Real", "Values": ["match-me"]},
    }], _fixed("BY-HTTP-HEADER"))
    _create_rule(ctx, la, 30, [{
        "Field": "http-request-method",
        "HttpRequestMethodConfig": {"Values": ["PUT"]},
    }], _fixed("BY-REQUEST-METHOD"))
    _create_rule(ctx, la, 40, [{
        "Field": "query-string",
        "QueryStringConfig": {"Values": [{"Key": "sim2real", "Value": "yes"}]},
    }], _fixed("BY-QUERY-STRING"))
    _create_rule(ctx, la, 50, [{
        "Field": "path-pattern",
        "PathPatternConfig": {"Values": ["/sim2real/deep/*"]},
    }], _fixed("BY-PATH-PATTERN"))

    # The typed sub-configs must survive the round trip, not be silently dropped.
    rules = {str(r["Priority"]): r for r in ctx.client("elbv2").describe_rules(ListenerArn=la)["Rules"]}
    assert rules["10"]["Conditions"][0].get("HostHeaderConfig", {}).get("Values") == [host_value], \
        rules["10"]["Conditions"]
    hdr_cfg = rules["20"]["Conditions"][0].get("HttpHeaderConfig", {})
    assert hdr_cfg.get("HttpHeaderName") == "X-Sim2Real", rules["20"]["Conditions"]
    assert hdr_cfg.get("Values") == ["match-me"], rules["20"]["Conditions"]
    assert rules["30"]["Conditions"][0].get("HttpRequestMethodConfig", {}).get("Values") == ["PUT"], \
        rules["30"]["Conditions"]
    assert rules["40"]["Conditions"][0].get("QueryStringConfig", {}).get("Values") == \
        [{"Key": "sim2real", "Value": "yes"}], rules["40"]["Conditions"]

    dns = lb["DNSName"]
    base = f"http://{dns}"

    # Warm the data plane on the unambiguous path-pattern rule first.
    _wait_for_body(
        ctx, f"{base}/sim2real/deep/x", "BY-PATH-PATTERN",
        description="path-pattern rule answering once the ALB data plane is serving",
    )

    # Positive: each condition type decides on its own signal.
    _assert_body(ctx, f"{base}/", "BY-HOST-HEADER", headers={"Host": host_value})
    _assert_body(ctx, f"{base}/", "BY-HTTP-HEADER", headers={"X-Sim2Real": "match-me"})
    _assert_body(ctx, f"{base}/", "BY-REQUEST-METHOD", method="PUT")
    _assert_body(ctx, f"{base}/?sim2real=yes", "BY-QUERY-STRING")

    # Negative: a near-miss on each signal must NOT match the rule.
    _assert_body(ctx, f"{base}/", "DEFAULT-RULE")
    _assert_body(ctx, f"{base}/", "DEFAULT-RULE", headers={"Host": "sim2real-behav-other.example.com"})
    _assert_body(ctx, f"{base}/", "DEFAULT-RULE", headers={"X-Sim2Real": "do-not-match"})
    _assert_body(ctx, f"{base}/?sim2real=no", "DEFAULT-RULE")
    _assert_body(ctx, f"{base}/sim2real/shallow", "DEFAULT-RULE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
