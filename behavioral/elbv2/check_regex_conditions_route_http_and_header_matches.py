"""regex-conditions-route-http-and-header-matches."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regex-conditions-route-http-and-header-matches"
GROUP = "rule-conditions"
SERVICES = ["ec2", "elbv2"]

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _clamp(name, maxlen=32):
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


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last observed: {last!r}")


def _get(ctx, url, *, headers=None, timeout=20):
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _security_group(ctx, vpc_id, port=80):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 regex-condition routing check ingress",
        VpcId=vpc_id,
    )["GroupId"]

    def _drop_sg():
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


def _create_load_balancer(ctx, subnet_ids, sg_id):
    elb = ctx.client("elbv2")
    name = _clamp(ctx.unique_name("sim2real-behav-lb-"))
    lb = _retry_throttled(lambda: elb.create_load_balancer(
        Name=name, Subnets=subnet_ids, Type="application", Scheme="internet-facing",
        SecurityGroups=[sg_id],
    ))["LoadBalancers"][0]
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


def _wait_for_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=10,
        description="load balancer reaching a terminal provisioning state",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_listener(ctx, lb_arn):
    elb = ctx.client("elbv2")
    listener = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{
            "Type": "fixed-response",
            "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "DEFAULT"},
        }],
    ))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return arn


def _fixed(body):
    return [{
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": body},
    }]


def _wait_for_body(ctx, url, expected, *, headers=None, timeout_s=300):
    seen = []

    def probe():
        try:
            status, body = _get(ctx, url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body[:60]!r}")
        return status, body

    got = _poll_until(
        probe, lambda r: r is not None and r[1].strip() == expected,
        timeout_s=timeout_s, interval_s=5,
        description=f"GET {url} headers={headers} serving {expected!r} (observed: {seen[-6:]})",
    )
    assert got[0] == 200, f"GET {url} headers={headers}: HTTP {got[0]}, body={got[1][:200]!r}"
    return got


def _assert_body(ctx, url, expected, *, headers=None):
    status, body = _get(ctx, url, headers=headers)
    assert status == 200, f"GET {url} headers={headers}: HTTP {status}, body={body[:200]!r}"
    assert body.strip() == expected, (
        f"GET {url} headers={headers}: routed to {body.strip()!r}, expected {expected!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A path-pattern or http-header condition given only as RegexValues is accepted and used to
    route HTTP requests, matching the regular expression rather than a wildcard glob."""
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    assert len(subnet_ids) >= 2, f"shared network exposes {len(subnet_ids)} subnets, need 2"
    sg_id = _security_group(ctx, net.vpc_id, 80)

    lb = _create_load_balancer(ctx, subnet_ids, sg_id)
    la = _create_listener(ctx, lb["LoadBalancerArn"])
    elb = ctx.client("elbv2")

    path_regex = "^/(allowed|also-allowed)$"
    header_regex = "^(yes|sure)$"

    path_rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=la, Priority=10,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"RegexValues": [path_regex]}}],
        Actions=_fixed("BY-PATH-REGEX"),
    ))["Rules"][0]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=path_rule["RuleArn"]))

    header_rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=la, Priority=20,
        Conditions=[{
            "Field": "http-header",
            "HttpHeaderConfig": {"HttpHeaderName": "x-match", "RegexValues": [header_regex]},
        }],
        Actions=_fixed("BY-HEADER-REGEX"),
    ))["Rules"][0]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=header_rule["RuleArn"]))

    rules = {r["Priority"]: r for r in elb.describe_rules(ListenerArn=la)["Rules"]}
    assert sorted(rules) == ["10", "20", "default"], f"listener holds rules {sorted(rules)!r}"

    path_cond = rules["10"]["Conditions"][0]
    assert path_cond["Field"] == "path-pattern", f"unexpected condition field {path_cond['Field']!r}"
    assert path_cond["PathPatternConfig"] == {"RegexValues": [path_regex]}, (
        f"path-pattern condition echoed as {path_cond['PathPatternConfig']!r}, expected only "
        f"RegexValues={[path_regex]!r}"
    )
    assert "Values" not in path_cond, f"a RegexValues-only condition echoed a legacy Values key: {path_cond!r}"

    header_cond = rules["20"]["Conditions"][0]
    assert header_cond["Field"] == "http-header", f"unexpected condition field {header_cond['Field']!r}"
    assert header_cond["HttpHeaderConfig"] == {"HttpHeaderName": "x-match", "RegexValues": [header_regex]}, (
        f"http-header condition echoed as {header_cond['HttpHeaderConfig']!r}"
    )

    _wait_for_active(ctx, lb["LoadBalancerArn"])
    base = ctx.endpoint_url(f"http://{lb['DNSName']}")

    # Warm the data plane, then prove the regex rules route by the pattern they declared.
    _wait_for_body(ctx, f"{base}/allowed", "BY-PATH-REGEX")
    _assert_body(ctx, f"{base}/also-allowed", "BY-PATH-REGEX")
    # Anchored: a path that merely starts with the matched word is not a match.
    _assert_body(ctx, f"{base}/allowedx", "DEFAULT")

    _assert_body(ctx, f"{base}/", "BY-HEADER-REGEX", headers={"x-match": "yes"})
    _assert_body(ctx, f"{base}/", "BY-HEADER-REGEX", headers={"x-match": "sure"})
    _assert_body(ctx, f"{base}/", "DEFAULT", headers={"x-match": "yessir"})
    _assert_body(ctx, f"{base}/", "DEFAULT")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
