"""create-rule-regex-and-value-condition-together-never-routes."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rule-regex-and-value-condition-together-never-routes"
GROUP = "negative-classes"
SERVICES = ["ec2", "elbv2"]

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_MIXED_CONDITION = (
    "ValidationError",
    "You must provide exactly one of the following: ['Values' 'RegexValues'] for config of "
    "type 'PathPatternConfig'",
)


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


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to be refused, but it succeeded")


def expect_error(fn, code, message):
    got_code, got_message = _error_code(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _security_group(ctx, vpc_id, port=80):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 regex-condition negative-check data-plane ingress",
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
    name = _clamp_name(ctx.unique_name("sim2real-behav-lb-"))
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


def _assert_body(ctx, url, expected, *, headers=None, method="GET"):
    status, _hdrs, body = _http(ctx, url, method=method, headers=headers)
    assert status == 200, f"{method} {url} headers={headers}: HTTP {status}, body={body[:200]!r}"
    assert body.strip() == expected, (
        f"{method} {url} headers={headers}: routed to {body.strip()!r}, expected {expected!r}"
    )


def _wait_for_body(ctx, url, expected, *, timeout_s=300, description=""):
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url)
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:data-plane",
      "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A path-pattern condition naming both Values and RegexValues in PathPatternConfig is
    refused and never routes a request, while a condition naming exactly one of them does."""
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    assert len(subnet_ids) >= 2, f"shared network exposes {len(subnet_ids)} subnets, need 2"
    sg_id = _security_group(ctx, net.vpc_id, 80)

    lb = _create_load_balancer(ctx, subnet_ids, sg_id)
    la = _create_listener(ctx, lb["LoadBalancerArn"])
    elb = ctx.client("elbv2")

    # Positive control: RegexValues alone is accepted.
    regex_rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=la, Priority=10,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"RegexValues": ["^/regex-only$"]}}],
        Actions=_fixed("BY-REGEX"),
    ))["Rules"][0]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=regex_rule["RuleArn"]))

    # Positive control: Values alone is accepted.
    values_rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=la, Priority=20,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/values-only"]}}],
        Actions=_fixed("BY-VALUES"),
    ))["Rules"][0]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=values_rule["RuleArn"]))

    # Negative: naming both in the same condition is refused outright.
    expect_error(
        lambda: elb.create_rule(
            ListenerArn=la, Priority=30,
            Conditions=[{
                "Field": "path-pattern",
                "PathPatternConfig": {"Values": ["/both"], "RegexValues": ["^/both$"]},
            }],
            Actions=_fixed("BY-BOTH"),
        ),
        *_MIXED_CONDITION,
    )

    rules = {r["Priority"]: r for r in elb.describe_rules(ListenerArn=la)["Rules"]}
    assert sorted(rules) == ["10", "20", "default"], (
        f"the listener holds rules {sorted(rules)!r}, the refused priority 30 must be absent"
    )

    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    dns = lb["DNSName"]
    base = f"http://{dns}"

    # Warm the data plane, then prove the two surviving rules route as configured.
    _wait_for_body(ctx, f"{base}/regex-only", "BY-REGEX",
                   description="path-pattern regex rule answering once the ALB is serving")
    _assert_body(ctx, f"{base}/values-only", "BY-VALUES")

    # The refused rule never took effect: a request for its intended path still falls through
    # to the default action rather than being served by a rule that was never created.
    _assert_body(ctx, f"{base}/both", "DEFAULT")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
