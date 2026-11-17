"""regex-condition-matches-and-falls-through-on-near-miss."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regex-condition-matches-and-falls-through-on-near-miss"
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


def _delete_retrying(fn, *, gone, busy=(), timeout_s=0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _http(ctx, url, *, method="GET", headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _shared_vpc_and_subnets(ctx, num_subnets=2):
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
        _delete_retrying(lambda: ec2.delete_security_group(GroupId=sg_id),
                          gone={"InvalidGroup.NotFound"}, busy={"DependencyViolation"}, timeout_s=300)

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


def _create_rule(ctx, listener_arn, priority, conditions, body):
    elb = ctx.client("elbv2")
    rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=priority, Conditions=conditions,
        Actions=_fixed(body), Tags=list(_TAGS),
    ))["Rules"][0]
    arn = rule["RuleArn"]

    def _drop_rule():
        try:
            elb.delete_rule(RuleArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RuleNotFound":
                raise

    ctx.on_cleanup(_drop_rule)
    return rule


def _wait_for_body(ctx, url, expected, *, headers=None, timeout_s=300, description=""):
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body.strip()[:60]}")
        return body.strip()

    got = _poll_until(
        probe, lambda r: r == expected, timeout_s=timeout_s, interval_s=5,
        description=description or f"{url} headers={headers} serving {expected!r} (observed: {seen[-6:]})",
    )
    return got
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A host-header or path-pattern condition built from RegexValues routes a request that
    matches the pattern's anchors and character classes, and a near-miss falls through to the
    default action, exercising regex semantics distinct from the wildcard Values matcher.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/rule-condition-types.html
    """
    vpc_id, subnet_ids = _shared_vpc_and_subnets(ctx)
    sg_id = _open_http_sg(ctx, vpc_id, 80)

    lb = _create_load_balancer(ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP", DefaultActions=_fixed("DEFAULT"),
    )
    la = listener["ListenerArn"]
    base = f"http://{lb['DNSName']}"

    # Warm the data plane on an unambiguous request before any regex rule exists.
    _wait_for_body(ctx, f"{base}/warm", "DEFAULT", description="default action answering once serving")

    host_rule = _create_rule(ctx, la, 10, [{
        "Field": "host-header",
        "HostHeaderConfig": {"RegexValues": [r"^(en|fr)\.sim2real-behav\.example\.com$"]},
    }], "HOST-REGEX-MATCH")

    path_rule = _create_rule(ctx, la, 20, [{
        "Field": "path-pattern",
        "PathPatternConfig": {"RegexValues": [r"^/articles/[0-9]+$"]},
    }], "PATH-REGEX-MATCH")

    # The RegexValues sub-config round-trips through DescribeRules rather than being silently
    # dropped or folded into Values.
    rules = {str(r["Priority"]): r for r in ctx.client("elbv2").describe_rules(ListenerArn=la)["Rules"]}
    assert rules["10"]["Conditions"][0].get("HostHeaderConfig", {}).get("RegexValues") == \
        [r"^(en|fr)\.sim2real-behav\.example\.com$"], rules["10"]["Conditions"]
    assert rules["20"]["Conditions"][0].get("PathPatternConfig", {}).get("RegexValues") == \
        [r"^/articles/[0-9]+$"], rules["20"]["Conditions"]

    # Positive: each alternative in the host-header regex's alternation matches.
    got = _wait_for_body(ctx, f"{base}/", "HOST-REGEX-MATCH",
                          headers={"Host": "en.sim2real-behav.example.com"},
                          description="host-header regex rule answering once serving")
    assert got == "HOST-REGEX-MATCH", got
    assert _http(ctx, f"{base}/", headers={"Host": "fr.sim2real-behav.example.com"})[2].strip() == \
        "HOST-REGEX-MATCH"

    # Negative control: a host outside the (en|fr) alternation must NOT match.
    status, _hdrs, body = _http(ctx, f"{base}/", headers={"Host": "de.sim2real-behav.example.com"})
    assert (status, body.strip()) == (200, "DEFAULT"), (
        f"host de.sim2real-behav.example.com outside the (en|fr) alternation was served "
        f"{(status, body.strip())!r}, expected the default action"
    )

    # Positive: the path regex matches one or more digits, anchored at both ends.
    status, _hdrs, body = _http(ctx, f"{base}/articles/42")
    assert (status, body.strip()) == (200, "PATH-REGEX-MATCH"), (
        f"/articles/42 against ^/articles/[0-9]+$ was served {(status, body.strip())!r}"
    )

    # Negative control: trailing non-digit content breaks the $ anchor.
    status, _hdrs, body = _http(ctx, f"{base}/articles/42a")
    assert (status, body.strip()) == (200, "DEFAULT"), (
        f"/articles/42a was served {(status, body.strip())!r}, expected the default action "
        f"because the regex is anchored with $ after one or more digits"
    )

    # Negative control: no digits at all breaks the character class.
    status, _hdrs, body = _http(ctx, f"{base}/articles/")
    assert (status, body.strip()) == (200, "DEFAULT"), (
        f"/articles/ was served {(status, body.strip())!r}, expected the default action"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
