"""target-response-exceeding-idle-timeout-yields-504."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-response-exceeding-idle-timeout-yields-504"
GROUP = 'error-semantics'
SERVICES = ['elbv2']

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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the check's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the check's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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


def _own_vpc_and_subnets(ctx, num_subnets=2):
    """A routable VPC and public subnets this check creates for the internet-facing load balancer."""
    return _own_public_vpc(ctx, n_subnets=num_subnets)


def _http_sg(ctx, vpc_id, source, ports=(80,)):
    """A security group admitting tcp *ports* from *source* (IpRanges or UserIdGroupPairs)."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        # The ALB's ENIs hold this group; the delete is retried until they are released,
        # which is the classic causeless DependencyViolation on teardown.
        last = None
        for _ in range(150):
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidGroup.NotFound":
                    return
                last = exc
                time.sleep(2)
        raise AssertionError(f"security group {sg_id} could not be deleted: {last!r}")

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": p, "ToPort": p, **source,
        } for p in ports],
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
        last = None
        for _ in range(90):
            try:
                last = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)
        raise RuntimeError(f"load balancer {arn} was not deleted: {last!r}")

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        ctx,
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=2,
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


def _create_rule(ctx, listener_arn, priority, path_values, body, status="200"):
    elb = ctx.client("elbv2")
    rule = _retry_throttled(lambda: elb.create_rule(
        ListenerArn=listener_arn, Priority=priority,
        Conditions=[{"Field": "path-pattern",
                     "PathPatternConfig": {"Values": list(path_values)}}],
        Actions=_fixed(body, status), Tags=list(_TAGS),
    ))["Rules"][0]
    arn = rule["RuleArn"]

    def _drop_rule():
        try:
            elb.delete_rule(RuleArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RuleNotFound":
                raise
            return

    ctx.on_cleanup(_drop_rule)
    return rule


def _wait_for_body(ctx, url, expected, *, timeout_s=300, headers=None):
    """Poll until the load balancer serves exactly `expected` (body, or (status, body)).

    A configuration change reaches the data plane asynchronously, so every leg polls the
    request rather than asserting once; the poll is BOUNDED so a load balancer that never
    changes behaviour fails instead of hanging.
    """
    seen = []

    def probe():
        try:
            status, _hdrs, body = _http(ctx, url, headers=headers)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        seen.append(f"{status}:{body.strip()[:40]}")
        return (status, body)

    def matches(r):
        if r is None:
            return False
        if isinstance(expected, tuple):
            return (r[0], r[1].strip()) == expected
        return r[1].strip() == expected

    return _poll_until(
        ctx,
        probe, matches, timeout_s=timeout_s, interval_s=2,
        description=f"load balancer serving {expected!r} at {url} (observed: {seen[-8:]})",
    )
def _safe(fn, gone):
    """Teardown step that treats only the resource's not-found code `gone` as done; raises the rest."""

    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != gone:
                raise

    return _wrapped


def _usable_az_subnets(ctx, vpc_id, want="t3.micro", n=2):
    """Subnets in AZs that really offer `want`.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone STATE,
    and describe_availability_zones says nothing about instance types. Letting AWS choose is
    how a subnet lands in an AZ that cannot run the instance type and RunInstances fails
    'Unsupported' - an error that reads exactly like a fidelity failure.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = offered & available
    assert usable, (
        f"no available AZ in {ctx.region} offers {want!r}; offerings were {sorted(offered)!r}"
    )
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]},
    ])["Subnets"]
    per_az = {}
    for sub in sorted(subnets, key=lambda s: s["SubnetId"]):
        if sub["AvailabilityZone"] in usable:
            per_az.setdefault(sub["AvailabilityZone"], sub["SubnetId"])
    picked = [per_az[az] for az in sorted(per_az)][:n]
    if len(picked) < n:
        raise AssertionError(
            f"VPC {vpc_id} exposes {len(picked)} subnets in AZs offering {want}, "
            f"need {n} (usable AZs: {sorted(usable)})"
        )
    return picked


def _describe_instance(ec2, iid, ctx=None):
    """DescribeInstances tolerating the eventual consistency right after RunInstances.

    DescribeInstances can answer InvalidInstanceID.NotFound for an instance id RunInstances has
    just returned, so that answer is retried.
    """
    deadline = time.monotonic() + (120 if ctx is None else _budget_s(ctx, 120))
    last = None
    while time.monotonic() < deadline:
        try:
            return ec2.describe_instances(InstanceIds=[iid])[
                "Reservations"][0]["Instances"][0]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                raise
            last = exc
        except (IndexError, KeyError) as exc:
            last = exc
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"instance {iid} appearing in DescribeInstances: the run budget "
                           f"ended first; not graded")
    raise AssertionError(f"instance {iid} never appeared in DescribeInstances: {last!r}")


def _launch_backend(ctx, subnet_id, sg_id, user_data, *, want="t3.micro"):
    """One EC2 instance running an HTTP backend from user-data, tagged AT CREATION.

    The AMI comes from the SSM public parameter rather than a hardcoded id: an image id is
    region-specific and goes stale, and a stale id fails in a way that reads like a fidelity
    defect.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-behav-ec2-")
    tags = list(_TAGS) + [{"Key": "Name", "Value": name}]
    inst = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id], UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags},
            {"ResourceType": "volume", "Tags": tags},
        ],
    )["Instances"][0]
    iid = inst["InstanceId"]

    def _drop_instance():
        for _ in range(20):
            try:
                ec2.terminate_instances(InstanceIds=[iid])
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                    raise
                time.sleep(3)
        # Wait for 'terminated', not just for the API to return: the instance's ENI holds the
        # security group, and an ENI holder is the classic cause of a causeless
        # DependencyViolation on the security-group delete that runs after this one.
        state = None
        for _ in range(150):
            try:
                found = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                    raise
                return
            if not found or not found[0].get("Instances"):
                return
            state = found[0]["Instances"][0]["State"]["Name"]
            if state == "terminated":
                return
            time.sleep(2)
        raise RuntimeError(f"instance {iid} was not deleted: {state!r}")

    ctx.on_cleanup(_drop_instance)
    _poll_until(
        ctx,
        lambda: _describe_instance(ec2, iid, ctx)["State"]["Name"],
        lambda s: s in ("running", "terminated", "shutting-down"),
        timeout_s=300, interval_s=2,
        description=f"instance {iid} reaching a terminal launch state",
    )
    described = _describe_instance(ec2, iid, ctx)
    assert described["State"]["Name"] == "running", (
        f"instance {iid} state {described['State']['Name']!r}, expected running"
    )
    return {"id": iid, "private_ip": described["PrivateIpAddress"]}


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        last = None
        for _ in range(10):
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "TargetGroupNotFound":
                    return
                last = exc
                time.sleep(4)
        raise RuntimeError(f"target group {arn} was not deleted: {last!r}")

    ctx.on_cleanup(_drop_tg)
    return tg


def _target_health(ctx, tg_arn, target):
    elb = ctx.client("elbv2")
    got = elb.describe_target_health(TargetGroupArn=tg_arn, Targets=[target])
    descs = got["TargetHealthDescriptions"]
    if not descs:
        return None
    return descs[0]["TargetHealth"]


def _wait_target_state(ctx, tg_arn, target, wanted, *, timeout_s=420):
    seen = []

    def probe():
        health = _target_health(ctx, tg_arn, target)
        seen.append(None if health is None else
                    f"{health.get('State')}/{health.get('Reason')}")
        return health

    return _poll_until(
        ctx,
        probe, lambda h: h is not None and h.get("State") == wanted,
        timeout_s=timeout_s, interval_s=2,
        description=f"target {target!r} in {tg_arn.rsplit('/', 2)[-2]} reaching state "
                    f"{wanted!r} (observed: {seen[-10:]})",
    )


def _forward(target_groups, sticky=None):
    cfg = {"TargetGroups": target_groups}
    if sticky is not None:
        cfg["TargetGroupStickinessConfig"] = sticky
    return [{"Type": "forward", "ForwardConfig": cfg}]


#: The key has no routing.http. prefix; "routing.http.idle_timeout.timeout_seconds" is rejected
#: with ValidationError "Load balancer attribute key ... is not recognized".
_ATTR = "idle_timeout.timeout_seconds"
_IDLE_S = 5
_SLEEP_S = 25
_MARKER = "SIM2REAL-TARGET-BODY"
#: `?s=<seconds>` makes the backend take that long to answer. The health-check path is
#: unaffected, so the target stays healthy across every leg and cannot be blamed for the 504.
_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import socketserver
import time

MARKER = "%s"


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parts = self.path.split("?", 1)
        secs = 0.0
        if len(parts) > 1:
            for kv in parts[1].split("&"):
                if kv.startswith("s="):
                    try:
                        secs = float(kv[2:])
                    except ValueError:
                        secs = 0.0
        time.sleep(secs)
        body = MARKER.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


S(("", 80), H).serve_forever()
PYEOF_INNER
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
""" % _MARKER


def _set_lb_attribute(ctx, lb_arn, key, value):
    """Set one load balancer attribute and poll until it READS BACK, which is the observable
    control-plane condition; the data-plane effect is polled separately by the caller."""
    elb = ctx.client("elbv2")
    _retry_throttled(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn, Attributes=[{"Key": key, "Value": value}]))
    _poll_until(
        ctx,
        lambda: {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
            LoadBalancerArn=lb_arn)["Attributes"]}.get(key),
        lambda v: v == value, timeout_s=120, interval_s=2,
        description=f"load balancer attribute {key} reading back {value!r}",
    )


# timing:real-time — lease: 5 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-load-balancer-attributes.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5", "timing:real-time",
)
def run(ctx) -> None:
    """A target slower than the load balancer's idle timeout gets a 504 and its body never reaches
    the client; the same target answers 200 with a zero sleep before and after, so the 504 is due
    to elapsed time alone."""
    elb = ctx.client("elbv2")
    vpc_id, _own_subnets = _own_vpc_and_subnets(ctx)
    subnet_ids = _usable_az_subnets(ctx, vpc_id, n=2)
    # The load balancer admits the caller's CIDRs; the instance admits only the load balancer's group.
    sg_id = _http_sg(ctx, vpc_id, {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _http_sg(ctx, vpc_id, {"UserIdGroupPairs": [{"GroupId": sg_id}]})

    inst = _launch_backend(ctx, subnet_ids[0], be_sg, _USER_DATA)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    lb_arn = lb["LoadBalancerArn"]
    _wait_for_lb_active(ctx, lb_arn)

    attrs_before = {a["Key"]: a["Value"] for a in elb.describe_load_balancer_attributes(
        LoadBalancerArn=lb_arn)["Attributes"]}
    default_idle = attrs_before.get(_ATTR)
    assert default_idle == "60", (
        f"a fresh ALB reports {_ATTR} as {default_idle!r}, expected the documented default "
        f"'60'; attributes present were {sorted(attrs_before)!r}"
    )
    # Restore the timeout before anything is torn down, so a partial teardown cannot leave a
    # 5-second idle timeout on a load balancer a later run might still be looking at.
    ctx.on_cleanup(_safe(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn, Attributes=[{"Key": _ATTR, "Value": default_idle}]),
        "LoadBalancerNotFound"))

    # An instance target, not Lambda: the idle timeout does not apply to a Lambda target's think
    # time (with a 1 s timeout a Lambda sleeping 20 s still answers 200).
    tg = _create_target_group(
        ctx, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/health",
        HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=4,
        HealthyThresholdCount=2, UnhealthyThresholdCount=5,
        Matcher={"HttpCode": "200"},
    )
    tg_arn = tg["TargetGroupArn"]
    target = {"Id": inst["id"], "Port": 80}
    _retry_throttled(lambda: elb.register_targets(TargetGroupArn=tg_arn, Targets=[target]))
    ctx.on_cleanup(_safe(lambda: elb.deregister_targets(
        TargetGroupArn=tg_arn, Targets=[target]), "TargetGroupNotFound"))

    listener = _create_listener(
        ctx, lb_arn, Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    assert listener["ListenerArn"], f"listener not created: {listener!r}"
    _wait_target_state(ctx, tg_arn, target, "healthy")

    fast_url = f"http://{lb['DNSName']}/?s=0"
    slow_url = f"http://{lb['DNSName']}/?s={_SLEEP_S}"

    # POSITIVE CONTROL, before: the target works with the default idle timeout.
    fast_status_before, fast_body_before = _wait_for_body(ctx, fast_url, _MARKER)
    assert fast_status_before == 200 and _MARKER in fast_body_before, (
        f"the target did not work before the timeout was configured: "
        f"HTTP {fast_status_before!r} body {fast_body_before[:120]!r}"
    )

    _set_lb_attribute(ctx, lb_arn, _ATTR, str(_IDLE_S))

    seen = []

    def _probe_slow():
        started = time.monotonic()
        try:
            status, _hdrs, body = _http(ctx, slow_url, timeout=_budget_s(ctx, 120))
        except (urllib.error.URLError, OSError) as exc:
            seen.append(f"<transport: {exc}>")
            return None
        elapsed = time.monotonic() - started
        seen.append(f"{status}:{elapsed:.1f}s")
        return (status, body, elapsed)

    slow_status, slow_body, slow_elapsed_s = _poll_until(
        ctx,
        _probe_slow, lambda r: r is not None and r[0] != 200,
        timeout_s=420, interval_s=2,
        description=f"a {_SLEEP_S}s target response being refused once {_ATTR}={_IDLE_S} "
                    f"reached the data plane (observed: {seen[-8:]})",
    )
    assert slow_status == 504, (
        f"a target response exceeding the idle timeout returned HTTP {slow_status!r}, "
        f"expected 504"
    )
    # EFFECT ABSENT: the body the target really produced never reached the client.
    assert _MARKER not in slow_body, (
        f"the timed-out response still carried the target body: {slow_body[:200]!r}"
    )
    # A LOWER bound only: an upper bound would assert a timing guarantee AWS does not make.
    assert slow_elapsed_s >= float(_IDLE_S), (
        f"the client was refused after only {slow_elapsed_s!r}s with a {_IDLE_S}s idle "
        f"timeout, so the 504 did not come from the timer"
    )
    # ...and the target was never withdrawn: the 504 is the timer's, not a health failure.
    health = _target_health(ctx, tg_arn, target)
    assert health is not None and health.get("State") == "healthy", (
        f"the target was {health!r} when the 504 was returned, so the refusal may be a "
        f"health withdrawal rather than the idle timer"
    )

    # POSITIVE CONTROL, after: with the timeout restored the SAME target serves again.
    _set_lb_attribute(ctx, lb_arn, _ATTR, default_idle)
    fast_status_after, fast_body_after = _wait_for_body(ctx, fast_url, _MARKER)
    assert fast_status_after == 200 and _MARKER in fast_body_after, (
        f"the target no longer works after the timeout test: HTTP {fast_status_after!r} "
        f"body {fast_body_after[:120]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


_NET_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _net_safe_cleanup(fn):
    """Teardown-only tolerance of an already-gone resource. Never used on an assertion path."""
    from botocore.exceptions import ClientError as _ClientError

    def _wrapped():
        try:
            fn()
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if not (code.endswith(".NotFound") or code == "Gateway.NotAttached"):
                raise

    return _wrapped


def _own_public_vpc(ctx, cidr="10.174.0.0/16", n_subnets=2, want="t3.micro"):
    """A VPC this check creates, with an internet gateway and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_NET_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_net_safe_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    ]
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    azs = sorted(z for z in azs if z in offered)
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs offering {want}, need {n_subnets}")

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _net_safe_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _net_safe_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_net_safe_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(_net_safe_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_net_safe_cleanup(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnet_ids


# Network deletes wait (bounded) for the ENIs a load balancer or function leaves behind, retrying
# DependencyViolation inside one shared window, and raise a final failure naming the ENIs.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]
