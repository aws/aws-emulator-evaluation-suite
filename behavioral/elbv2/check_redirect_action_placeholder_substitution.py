"""redirect-action-placeholder-substitution."""
from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redirect-action-placeholder-substitution"
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
    """Never follow the 3xx — the Location header IS the assertion."""

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
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
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


def _wait_for_status(ctx, url, expected_status, *, timeout_s=300, description=""):
    seen = []

    def probe():
        try:
            status, hdrs, body = _http(ctx, url)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}")
        return (status, hdrs, body)

    return _poll_until(
        probe, lambda r: r is not None and r[0] == expected_status,
        timeout_s=timeout_s, interval_s=5,
        description=description or f"GET {url} answering HTTP {expected_status} (observed: {seen[-6:]})",
    )
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A redirect action expands #{host}/#{path}/#{port}/#{query} into the Location header (#{path}
    without its leading slash, #{query} raw, #{port} as received), leaves no literal #{, honors the
    configured 301/302 per rule, and passes a literal Host through unchanged."""
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

    placeholder_rule = _create_rule(ctx, la, 10, [
        {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/redir/*"]}},
    ], [{
        "Type": "redirect",
        "RedirectConfig": {
            "Protocol": "HTTPS",
            "Host": "#{host}",
            "Port": "8443",
            "Path": "/moved#{path}",
            "Query": "orig=#{path}&keep=#{query}",
            "StatusCode": "HTTP_301",
        },
    }])
    _create_rule(ctx, la, 20, [
        {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/perm/*"]}},
    ], [{
        "Type": "redirect",
        "RedirectConfig": {
            "Protocol": "HTTPS",
            "Host": "sim2real-behav-elsewhere.example.com",
            "Port": "443",
            "Path": "/fixed",
            "StatusCode": "HTTP_302",
        },
    }])
    # ELBv2's own documented default Path: because #{path} carries no leading slash, "/#{path}"
    # must reproduce the request path EXACTLY. An implementation that includes the slash in the
    # placeholder emits "//dflt/deep/thing" here and is caught.
    _create_rule(ctx, la, 30, [
        {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/dflt/*"]}},
    ], [{
        "Type": "redirect",
        "RedirectConfig": {
            "Protocol": "HTTPS",
            "Host": "#{host}",
            "Port": "8443",
            "Path": "/#{path}",
            "StatusCode": "HTTP_301",
        },
    }])
    # #{port} is the port the request ARRIVED on (80 here), not 443 just because the redirect
    # protocol is HTTPS -- and #{query} lands in the query string verbatim.
    _create_rule(ctx, la, 40, [
        {"Field": "path-pattern", "PathPatternConfig": {"Values": ["/pq/*"]}},
    ], [{
        "Type": "redirect",
        "RedirectConfig": {
            "Protocol": "HTTPS",
            "Host": "#{host}",
            "Port": "#{port}",
            "Path": "/p",
            "Query": "q=#{query}",
            "StatusCode": "HTTP_302",
        },
    }])

    # The RedirectConfig must round-trip verbatim, placeholders included.
    cfg = placeholder_rule["Actions"][0]["RedirectConfig"]
    assert cfg["Host"] == "#{host}", cfg
    assert cfg["Path"] == "/moved#{path}", cfg
    assert cfg["Query"] == "orig=#{path}&keep=#{query}", cfg
    assert cfg["StatusCode"] == "HTTP_301", cfg

    dns = lb["DNSName"]
    base = f"http://{dns}"

    # 1. Placeholder redirect: 301 with everything substituted.
    _status, hdrs, _body = _wait_for_status(ctx,
        f"{base}/redir/deep/thing?a=1&b=2", 301,
        description="placeholder redirect rule answering HTTP 301",
    )
    location = hdrs.get("Location")
    assert location, f"301 without a Location header; headers={dict(hdrs)!r}"
    assert "#{" not in location, f"redirect placeholders left unsubstituted in Location: {location!r}"
    parsed = urllib.parse.urlsplit(location)
    assert parsed.scheme == "https", location
    assert parsed.hostname == dns.lower(), f"#{{host}} not substituted with the request host: {location!r}"
    assert parsed.port == 8443, f"configured redirect port not applied: {location!r}"
    # #{path} carries NO leading slash, so "/moved#{path}" concatenates directly onto "moved".
    assert parsed.path == "/movedredir/deep/thing", f"#{{path}} substitution wrong: {location!r}"
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    assert query.get("orig") == ["redir/deep/thing"], f"#{{path}} in Query wrong: {location!r}"
    assert "a=1&b=2" in parsed.query, f"#{{query}} not substituted into Query: {location!r}"

    # 2. A second redirect rule honors its own (different) status code and literal Host.
    _status2, hdrs2, _b2 = _wait_for_status(ctx,
        f"{base}/perm/anything", 302,
        description="literal-host redirect rule answering HTTP 302",
    )
    loc2 = hdrs2.get("Location")
    assert loc2, f"302 without a Location header; headers={dict(hdrs2)!r}"
    parsed2 = urllib.parse.urlsplit(loc2)
    assert parsed2.scheme == "https", loc2
    assert parsed2.hostname == "sim2real-behav-elsewhere.example.com", loc2
    assert parsed2.path == "/fixed", loc2
    assert parsed2.query == "", f"no Query configured but one was emitted: {loc2!r}"

    # 3. "/#{path}" -- the documented default -- reproduces the request path exactly, which is
    #    the direct proof that the placeholder excludes the leading slash.
    _status3a, hdrs3a, _b3a = _wait_for_status(ctx,
        f"{base}/dflt/deep/thing", 301,
        description="'/#{path}' redirect rule answering HTTP 301",
    )
    loc3a = hdrs3a.get("Location")
    parsed3a = urllib.parse.urlsplit(loc3a or "")
    assert parsed3a.path == "/dflt/deep/thing", (
        f"'/#{{path}}' must reproduce the request path exactly, got {loc3a!r}"
    )
    assert parsed3a.query == "", f"no Query configured but one was emitted: {loc3a!r}"

    # 4. #{port} is the arrival port, and #{query} is spliced in verbatim.
    _status4, hdrs4, _b4 = _wait_for_status(ctx,
        f"{base}/pq/x?z=9", 302,
        description="'#{port}'/'#{query}' redirect rule answering HTTP 302",
    )
    loc4 = hdrs4.get("Location")
    parsed4 = urllib.parse.urlsplit(loc4 or "")
    assert parsed4.scheme == "https", loc4
    assert parsed4.port == 80, (
        f"#{{port}} must expand to the port the request arrived on (80), not the redirect "
        f"protocol's default, got {loc4!r}"
    )
    assert parsed4.path == "/p", loc4
    assert parsed4.query == "q=z=9", (
        f"#{{query}} must be spliced in verbatim without re-encoding, got {loc4!r}"
    )

    # 5. Control: a request matching neither redirect still gets the default action,
    #    i.e. the redirect rules did not swallow unrelated traffic.
    _status3, _h3, body3 = _wait_for_status(ctx,
        f"{base}/untouched", 200,
        description="default action still serving requests that match no redirect rule",
    )
    assert body3.strip() == "DEFAULT-RULE", body3


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
