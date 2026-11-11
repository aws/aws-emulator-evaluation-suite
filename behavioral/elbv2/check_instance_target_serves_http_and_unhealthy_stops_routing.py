"""instance-target-serves-http-and-unhealthy-stops-routing."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-target-serves-http-and-unhealthy-stops-routing"
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
        for _ in range(50):
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidGroup.NotFound":
                    return
                last = exc
                time.sleep(6)
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
        probe, matches, timeout_s=timeout_s, interval_s=5,
        description=f"load balancer serving {expected!r} at {url} (observed: {seen[-8:]})",
    )
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


def _describe_instance(ec2, iid):
    """DescribeInstances tolerating the eventual consistency right after RunInstances.

    DescribeInstances can briefly return InvalidInstanceID.NotFound for an id RunInstances just
    returned, which reads exactly like a fidelity failure if it is not absorbed here.
    """
    last = None
    for _ in range(40):
        try:
            return ec2.describe_instances(InstanceIds=[iid])[
                "Reservations"][0]["Instances"][0]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                raise
            last = exc
        except (IndexError, KeyError) as exc:
            last = exc
        time.sleep(3)
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
        # TerminateInstances can answer NotFound just after RunInstances: retry that briefly.
        deadline = time.monotonic() + 30
        while True:
            try:
                ec2.terminate_instances(InstanceIds=[iid])
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                    raise
                if time.monotonic() >= deadline:
                    return
            time.sleep(2)
        # Wait for 'terminated': the instance's ENI holds the security group deleted after this.
        deadline = time.monotonic() + 240
        state = None
        while time.monotonic() < deadline:
            try:
                found = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                    return
                raise
            if not found:
                return
            state = found[0]["Instances"][0]["State"]["Name"]
            if state == "terminated":
                return
            time.sleep(2)
        raise AssertionError(f"instance {iid} is {state!r}, not terminated, 240 s after its terminate")

    ctx.on_cleanup(_drop_instance)
    _poll_until(
        lambda: _describe_instance(ec2, iid)["State"]["Name"],
        lambda s: s in ("running", "terminated", "shutting-down"),
        timeout_s=300, interval_s=5,
        description=f"instance {iid} reaching a terminal launch state",
    )
    described = _describe_instance(ec2, iid)
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
        # A listener or deleting load balancer holds the group briefly: retry only ResourceInUse.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

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
        probe, lambda h: h is not None and h.get("State") == wanted,
        timeout_s=timeout_s, interval_s=5,
        description=f"target {target!r} in {tg_arn.rsplit('/', 2)[-2]} reaching state "
                    f"{wanted!r} (observed: {seen[-10:]})",
    )


def _forward(target_groups, sticky=None):
    cfg = {"TargetGroups": target_groups}
    if sticky is not None:
        cfg["TargetGroupStickinessConfig"] = sticky
    return [{"Type": "forward", "ForwardConfig": cfg}]


# ===== end helpers =====


#: One instance, two labelled backends on two ports, and three health-check paths that split
#: them: /ok is 200 on both, /deny is 200 on A and 404 on B, /denyall is 404 on both. Changing
#: only the target group's HealthCheckPath therefore moves the SAME two targets through three
#: health configurations without touching the backends, the instance or the request.
_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import socketserver
import threading


def make(label, deny_prefix):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            path = self.path.split("?")[0]
            if path.startswith(deny_prefix):
                body, code = b"NOT-FOUND", 404
            else:
                body, code = label.encode(), 200
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return H


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


b = S(("", 8080), make("TARGET-B", "/deny"))
threading.Thread(target=b.serve_forever, daemon=True).start()
S(("", 80), make("TARGET-A", "/denyall")).serve_forever()
PYEOF_INNER
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
"""


def _sample_bodies(ctx, url, n):
    bodies = []
    for _ in range(n):
        status, _hdrs, body = _http(ctx, url)
        assert status == 200, f"GET {url}: HTTP {status}, body={body[:200]!r}"
        bodies.append(body.strip())
    return bodies


def _poll_bodies(ctx, url, predicate, description, *, n=20, timeout_s=300):
    seen = []

    def probe():
        """n requests' bodies, or None while any request fails or is not a 200."""
        bodies = []
        for _ in range(n):
            try:
                status, _hdrs, body = _http(ctx, url)
            except (urllib.error.URLError, OSError) as exc:
                seen.append(f"<{type(exc).__name__}: {str(exc)[:60]}>")
                return None
            if status != 200:
                seen.append(f"HTTP {status}: {body[:60]!r}")
                return None
            bodies.append(body.strip())
        seen.append(sorted(set(bodies)))
        return bodies

    return _poll_until(
        probe, lambda b: b is not None and predicate(b),
        timeout_s=timeout_s, interval_s=5,
        description=f"{description} (observed: {seen[-6:]})",
    )


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """EC2 instance targets serve their own bytes through an ALB, an unhealthy target beside a
    healthy sibling receives no requests, and a group whose every target is unhealthy fails open
    and is still served; only the target group's HealthCheckPath changes between legs."""
    elb = ctx.client("elbv2")
    vpc_id, _own_subnets = _own_vpc_and_subnets(ctx)
    subnet_ids = _usable_az_subnets(ctx, vpc_id, n=2)
    # The load balancer admits the runner; the instance admits both backend ports from the load
    # balancer's group only.
    sg_id = _http_sg(ctx, vpc_id, {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _http_sg(ctx, vpc_id, {"UserIdGroupPairs": [{"GroupId": sg_id}]}, ports=(80, 8080))

    inst = _launch_backend(ctx, subnet_ids[0], be_sg, _USER_DATA)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id],
    )
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(
        ctx, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/ok",
        HealthCheckPort="traffic-port",
        HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        Matcher={"HttpCode": "200"},
    )
    tg_arn = tg["TargetGroupArn"]
    target_a = {"Id": inst["id"], "Port": 80}
    target_b = {"Id": inst["id"], "Port": 8080}
    for target in (target_a, target_b):
        _retry_throttled(lambda t=target: elb.register_targets(
            TargetGroupArn=tg_arn, Targets=[t]))
        ctx.on_cleanup(_net_safe_cleanup(lambda t=target: elb.deregister_targets(
            TargetGroupArn=tg_arn, Targets=[t])))

    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    assert listener["ListenerArn"], f"listener not created: {listener!r}"

    url = f"http://{lb['DNSName']}/"

    # 1. Both instance targets healthy: both really serve their own bytes through the ALB.
    _wait_target_state(ctx, tg_arn, target_a, "healthy")
    _wait_target_state(ctx, tg_arn, target_b, "healthy")
    both_bodies = _poll_bodies(ctx,
        url, lambda b: set(b) == {"TARGET-A", "TARGET-B"},
        "both healthy instance targets serving through the load balancer",
    )
    assert set(both_bodies) == {"TARGET-A", "TARGET-B"}, (
        f"with both targets healthy the load balancer served {sorted(set(both_bodies))!r}, "
        f"expected both TARGET-A and TARGET-B"
    )

    # 2. Break exactly one thing — the health-check path — so B fails it and A does not.
    _retry_throttled(lambda: elb.modify_target_group(
        TargetGroupArn=tg_arn, HealthCheckPath="/deny"))
    unhealthy_b = _wait_target_state(ctx, tg_arn, target_b, "unhealthy")
    unhealthy_reason = unhealthy_b.get("Reason")
    assert unhealthy_reason == "Target.ResponseCodeMismatch", (
        f"a health check against a path the backend 404s reported Reason "
        f"{unhealthy_reason!r}, expected Target.ResponseCodeMismatch"
    )
    health_a = _target_health(ctx, tg_arn, target_a)
    assert health_a is not None and health_a.get("State") == "healthy", (
        f"the sibling target went {health_a!r} too; the /deny health path must leave "
        f"TARGET-A healthy or the withdrawal below is not attributable to health"
    )
    # EFFECT ABSENT: the unhealthy target receives NO requests while a healthy sibling exists.
    only_a = _poll_bodies(ctx,
        url, lambda b: set(b) == {"TARGET-A"},
        "the unhealthy target being withdrawn from routing while its sibling is healthy",
    )
    assert "TARGET-B" not in only_a, (
        f"the load balancer routed to an unhealthy target: {sorted(set(only_a))!r}, expected "
        f"only TARGET-A"
    )

    # 3. With EVERY target unhealthy the ALB fails open and keeps routing to all targets.
    _retry_throttled(lambda: elb.modify_target_group(
        TargetGroupArn=tg_arn, HealthCheckPath="/denyall"))
    _wait_target_state(ctx, tg_arn, target_a, "unhealthy")
    _wait_target_state(ctx, tg_arn, target_b, "unhealthy")
    failopen_bodies = _poll_bodies(ctx,
        url, lambda b: set(b) <= {"TARGET-A", "TARGET-B"} and len(b) == 8,
        "the load balancer failing open with every target unhealthy", n=8,
    )
    assert set(failopen_bodies) <= {"TARGET-A", "TARGET-B"} and failopen_bodies, (
        f"with every target unhealthy the load balancer served "
        f"{sorted(set(failopen_bodies))!r}; an ALB fails OPEN in that state and must still "
        f"route to its targets"
    )

    # 4. Undo the one broken thing: both targets recover and both serve again.
    _retry_throttled(lambda: elb.modify_target_group(
        TargetGroupArn=tg_arn, HealthCheckPath="/ok"))
    _wait_target_state(ctx, tg_arn, target_a, "healthy")
    _wait_target_state(ctx, tg_arn, target_b, "healthy")
    recovered = _poll_bodies(ctx,
        url, lambda b: set(b) == {"TARGET-A", "TARGET-B"},
        "both targets recovering once the health-check path is restored",
    )
    assert set(recovered) == {"TARGET-A", "TARGET-B"}, (
        f"after restoring the health-check path the load balancer served "
        f"{sorted(set(recovered))!r}, expected both TARGET-A and TARGET-B — so TARGET-B was "
        f"reachable and serving all along and was excluded by health alone"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

# ===== own network (self-contained) =====

_NET_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


# Not-found codes a teardown treats as already deleted; every other error raises.
_GONE = frozenset({
    "TargetGroupNotFound", "InvalidTarget", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound",
})


def _net_safe_cleanup(fn):
    """Wrap one teardown call: a resource already gone is fine; any other error raises."""
    from botocore.exceptions import ClientError as _ClientError

    def _wrapped():
        try:
            fn()
        except _ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                raise

    return _wrapped


def _own_public_vpc(ctx, cidr="10.171.0.0/16", n_subnets=2, want="t3.micro"):
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
