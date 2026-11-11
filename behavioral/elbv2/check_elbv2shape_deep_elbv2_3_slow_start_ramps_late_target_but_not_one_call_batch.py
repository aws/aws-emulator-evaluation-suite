"""elbv2shape-deep-elbv2-3-slow-start-ramps-late-target-but-not-one-call-batch."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elbv2shape-deep-elbv2-3-slow-start-ramps-late-target-but-not-one-call-batch"
GROUP = "data-plane"
SERVICES = ["elbv2"]

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_CIDR = "10.174.0.0/16"


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
    """Bounded retry. RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_GONE = {
    "InvalidVpcID.NotFound", "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
    "InvalidRouteTableID.NotFound", "InvalidSubnetID.NotFound", "InvalidAssociationID.NotFound",
    "InvalidInstanceID.NotFound", "ListenerNotFound", "TargetGroupNotFound", "InvalidTarget",
}


def _safe_cleanup(fn):
    """Teardown: done once the resource is gone; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") not in _GONE:
                raise

    return _wrapped


def _http(ctx, url, *, headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method="GET", headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _wait_serving(ctx, url, *, timeout_s=300):
    """Poll until the load balancer's DNS name resolves and a request is answered 200."""
    seen = []

    def probe():
        try:
            status, _h, body = _http(ctx, url, timeout=10)
        except (urllib.error.URLError, OSError) as exc:
            seen.append(type(exc).__name__)
            return None
        seen.append(status)
        return status

    _poll_until(probe, lambda s: s == 200, timeout_s=timeout_s, interval_s=5,
                description=f"{url} answering 200 (observed: {seen[-8:]})")


def _sample(ctx, url, n, *, workers=10):
    """n concurrent requests; every one must be a 200. -> Counter of response bodies."""
    def one(_):
        return _http(ctx, url)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(one, range(n)))
    bad = [(s, b[:80]) for s, _h, b in results if s != 200]
    assert not bad, f"{len(bad)}/{n} requests to {url} were not 200: {bad[:5]!r}"
    return Counter(b.strip() for _s, _h, b in results)


def _own_public_vpc(ctx, cidr=_CIDR, n_subnets=2):
    """A VPC this check creates, with an IGW and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = _azs_offering(ctx, "t3.micro")
    assert len(azs) >= n_subnets, (
        f"{ctx.region} exposes {len(azs)} available AZs offering t3.micro, need {n_subnets}"
    )

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _safe_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _safe_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_safe_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnets = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        subnets.append({"id": sid, "az": az})
        ctx.on_cleanup(_safe_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_safe_cleanup(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnets


def _azs_offering(ctx, instance_type):
    """AZs that are BOTH available and really offer `instance_type`."""
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    return usable


def _ingress_sg(ctx, vpc_id, ports, source):
    """A security group admitting tcp *ports* from *source* (IpRanges or UserIdGroupPairs)."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        last = None
        for _ in range(50):
            try:
                _delete_net(ec2, "delete_security_group", GroupId=sg_id)
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
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
             **source}
            for p in ports
        ],
    )
    return sg_id


def _describe_instance(ec2, iid, ctx=None):
    """DescribeInstances tolerating the eventual consistency right after RunInstances."""
    left = None if ctx is None else ctx.time_left()
    deadline = time.monotonic() + (120 if left is None else max(1.0, min(120, left - 5.0)))
    last = None
    while time.monotonic() < deadline:
        try:
            return ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                raise
            last = exc
        except (IndexError, KeyError) as exc:
            last = exc
        time.sleep(2)
    raise AssertionError(f"instance {iid} never appeared in DescribeInstances: {last!r}")


def _launch_backend(ctx, subnet_id, sg_id, user_data, *, want="t3.micro"):
    """One EC2 instance running HTTP backends from user-data, tagged AT CREATION."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-behav-ec2-")
    tagset = list(_TAGS) + [{"Key": "Name", "Value": name}]
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id], UserData=user_data,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tagset},
                           {"ResourceType": "volume", "Tags": tagset}],
    )["Instances"][0]["InstanceId"]

    def _drop_instance():
        _safe_cleanup(lambda: ec2.terminate_instances(InstanceIds=[iid]))()
        # Wait for 'terminated': the instance ENI holds the security group the next cleanup drops.
        deadline = time.monotonic() + 300
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
        raise AssertionError(f"instance {iid} is {state!r}, not terminated, 300s after its terminate")

    ctx.on_cleanup(_drop_instance)
    _poll_until(
        lambda: _describe_instance(ec2, iid, ctx)["State"]["Name"],
        lambda s: s in ("running", "terminated", "shutting-down"),
        timeout_s=300, interval_s=5,
        description=f"instance {iid} reaching a terminal launch state",
    )
    described = _describe_instance(ec2, iid, ctx)
    assert described["State"]["Name"] == "running", (
        f"instance {iid} state {described['State']['Name']!r}, expected running"
    )
    return iid


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(Name=name, Subnets=subnet_ids, Type="application",
                  Scheme="internet-facing", Tags=list(_TAGS))
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
    assert lb["State"]["Code"] == "active", (
        f"load balancer state {lb['State']!r}, expected State.Code == 'active'"
    )
    return lb


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # A target group stays ResourceInUse until its listener rules are released.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_tg)
    return tg


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(_safe_cleanup(lambda: elb.delete_listener(ListenerArn=arn)))
    return listener


def _wait_target_state(ctx, tg_arn, target, wanted, *, timeout_s=420, interval_s=5):
    elb = ctx.client("elbv2")
    seen = []

    def probe():
        descs = elb.describe_target_health(
            TargetGroupArn=tg_arn, Targets=[target])["TargetHealthDescriptions"]
        health = descs[0]["TargetHealth"] if descs else None
        seen.append(None if health is None else f"{health.get('State')}/{health.get('Reason')}")
        return health

    return _poll_until(
        probe, lambda h: h is not None and h.get("State") == wanted,
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"target {target!r} reaching state {wanted!r} (observed: {seen[-10:]})",
    )


def _set_tg_attributes(ctx, tg_arn, pairs):
    """Set attributes and assert the control plane reports them back before probing the data plane."""
    elb = ctx.client("elbv2")
    _retry_throttled(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": k, "Value": v} for k, v in pairs.items()],
    ))
    attrs = {a["Key"]: a["Value"] for a in elb.describe_target_group_attributes(
        TargetGroupArn=tg_arn)["Attributes"]}
    for key, value in pairs.items():
        assert attrs.get(key) == value, (
            f"DescribeTargetGroupAttributes reports {key}={attrs.get(key)!r} after setting it to "
            f"{value!r}"
        )
    return attrs


_BACKEND = r'''#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import json
import socketserver
import threading
import time

CONFIG = json.loads(r"""__CONFIG__""")
STATS = {"requests": 0, "max_path": 0, "max_headers": 0}
LOCK = threading.Lock()


def make(cfg):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            path = self.path
            cookie = None
            if path.startswith("/__stats"):
                with LOCK:
                    body = json.dumps(STATS).encode()
            else:
                if not path.startswith("/health"):
                    size = sum(len(k) + len(v) + 4 for k, v in self.headers.items())
                    with LOCK:
                        STATS["requests"] += 1
                        STATS["max_path"] = max(STATS["max_path"], len(path))
                        STATS["max_headers"] = max(STATS["max_headers"], size)
                    if cfg.get("delay"):
                        time.sleep(cfg["delay"])
                    if cfg.get("cookie") and not path.startswith("/nc"):
                        cookie = "%s=%s; Path=/" % (cfg["cookie"], cfg["label"])
                body = cfg["label"].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return H


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


servers = [S(("", int(p)), make(c)) for p, c in CONFIG.items()]
for s in servers[1:]:
    threading.Thread(target=s.serve_forever, daemon=True).start()
servers[0].serve_forever()
PYEOF_INNER
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
'''


def _backend_user_data(config):
    return _BACKEND.replace("__CONFIG__", json.dumps(config))
# ===== end helpers =====

#: The slow-start window under test. 120 s is far enough above the 30 s minimum that a sample
#: taken within the first few seconds after the new target turns healthy sits deep inside the
#: ramp, and short enough to wait out inside the check's budget.
_SLOW_START_S = 120
#: Requests per sample. Every sample in this check uses the same size and concurrency (the
#: in-window one stops early only at its deadline), so the shares are comparable with each
#: other — the check's baselines are its own measurements.
_N = 150
#: Fewest in-window requests whose shares are still comparable at _MARGIN.
_N_MIN = 100
#: Two shares are "equal" when they are within this much of each other, and "strictly below" when
#: the gap exceeds it. Sized for 150 requests split three ways (binomial sd ~0.04).
_MARGIN = 0.10
#: Settle time after the window nominally ends before the post-window sample is trusted.
_SETTLE_S = 20

_LABELS = {80: "TARGET-A", 8080: "TARGET-B", 8081: "TARGET-C"}


def _shares(counts, labels):
    total = sum(counts.values())
    return {lab: counts.get(lab, 0) / total for lab in labels}


# timing:real-time — cooldown: 120 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html
@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5", "timing:real-time")
def run(ctx) -> None:
    """Slow start ramps a target registered after a non-slow-start incumbent is healthy, and does
    NOT apply to targets registered together in one call on an empty slow-start group.
    """
    elb = ctx.client("elbv2")

    vpc_id, subnets = _own_public_vpc(ctx)
    subnet_ids = [s["id"] for s in subnets]
    # The load balancer admits the runner; the backend admits only the load balancer's group.
    sg_id = _ingress_sg(ctx, vpc_id, (80,), {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _ingress_sg(ctx, vpc_id, (80, 8080, 8081), {"UserIdGroupPairs": [{"GroupId": sg_id}]})
    config = {str(p): {"label": lab} for p, lab in _LABELS.items()}
    lb = _create_load_balancer(ctx, subnet_ids, SecurityGroups=[sg_id])
    iid = _launch_backend(ctx, subnet_ids[0], be_sg, _backend_user_data(config))

    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(
        ctx, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/health", HealthCheckPort="traffic-port",
        HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2, Matcher={"HttpCode": "200"},
    )
    tg_arn = tg["TargetGroupArn"]

    # Slow start on the EMPTY group — the precondition for beat 1.
    descs = elb.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    assert descs == [], f"a freshly created target group already has targets: {descs!r}"
    _set_tg_attributes(ctx, tg_arn, {
        "slow_start.duration_seconds": str(_SLOW_START_S),
        "deregistration_delay.timeout_seconds": "0",
    })

    target = {p: {"Id": iid, "Port": p} for p in _LABELS}
    for p in _LABELS:
        ctx.on_cleanup(_safe_cleanup(lambda t=target[p]: elb.deregister_targets(
            TargetGroupArn=tg_arn, Targets=[t])))

    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])

    # ---- beat 1: A and B in ONE RegisterTargets call. ---------------------------------------
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_arn, Targets=[target[80], target[8080]]))
    _wait_target_state(ctx, tg_arn, target[80], "healthy", interval_s=2)
    _wait_target_state(ctx, tg_arn, target[8080], "healthy", interval_s=2)
    url = f"http://{lb['DNSName']}/x"
    _wait_serving(ctx, url)

    p_counts = _sample(ctx, url, _N)
    p_share = _shares(p_counts, _LABELS.values())
    assert set(p_counts) == {"TARGET-A", "TARGET-B"}, (
        f"with only A and B registered, {_N} requests were served by {dict(p_counts)!r}"
    )
    assert abs(p_share["TARGET-A"] - p_share["TARGET-B"]) <= _MARGIN, (
        f"the two incumbents registered in one call took unequal shares {p_share!r} "
        f"(margin {_MARGIN}) — the baseline the rest of the check compares against is unusable"
    )

    # ---- beat 2: C alone, while A and B are healthy. ----------------------------------------
    _retry_throttled(lambda: elb.register_targets(TargetGroupArn=tg_arn, Targets=[target[8081]]))
    _wait_target_state(ctx, tg_arn, target[8081], "healthy", interval_s=1)
    t_healthy = time.monotonic()
    # The in-window sample is confined to the first half of C's window by construction: batches
    # stop at that deadline, so every request it counts was served while C was still ramping.
    w_counts = Counter()
    while sum(w_counts.values()) < _N and time.monotonic() < t_healthy + _SLOW_START_S / 2:
        w_counts.update(_sample(ctx, url, 10))
    w_elapsed = time.monotonic() - t_healthy
    # The last batch starts before the half-window deadline; allow it a short tail to finish.
    assert w_elapsed < _SLOW_START_S / 2 + 30, (
        f"the in-window sample finished {w_elapsed:.0f}s after C turned healthy, not inside the "
        f"first half of its {_SLOW_START_S}s window; the measurement does not test the ramp"
    )
    assert sum(w_counts.values()) >= _N_MIN, (
        f"only {sum(w_counts.values())} requests were served in the first half of C's "
        f"{_SLOW_START_S}s window; {_N_MIN} are needed to compare shares: {dict(w_counts)!r}"
    )
    w_share = _shares(w_counts, _LABELS.values())
    incumbent_floor = min(w_share["TARGET-A"], w_share["TARGET-B"])
    assert w_share["TARGET-C"] + _MARGIN < incumbent_floor, (
        f"{w_elapsed:.0f}s into C's {_SLOW_START_S}s slow-start window C took "
        f"{w_share['TARGET-C']:.3f} of {_N} requests vs incumbents {w_share!r}; it must be "
        f"strictly below each incumbent by more than {_MARGIN}. Equal-or-higher means C did not "
        f"enter slow start — either slow start is not implemented, or the one-call batch A+B was "
        f"wrongly put into slow start, leaving no healthy non-slow-start target. counts="
        f"{dict(w_counts)!r}"
    )
    assert abs(w_share["TARGET-A"] - w_share["TARGET-B"]) <= _MARGIN, (
        f"during C's window the incumbents diverged from each other: {w_share!r}"
    )

    # ---- beat 3: after the window, C is equal to the incumbents again. ----------------------
    # No API exposes the end of slow start; it is a documented timer anchored on the observed
    # healthy transition. Keep exercising the data plane until it has elapsed (plus settle).
    timeline = []
    while time.monotonic() < t_healthy + _SLOW_START_S + _SETTLE_S:
        c = _sample(ctx, url, 60)
        timeline.append((round(time.monotonic() - t_healthy), dict(c)))
        time.sleep(2)
    s_counts = _sample(ctx, url, _N)
    s_share = _shares(s_counts, _LABELS.values())
    incumbents_mean = (s_share["TARGET-A"] + s_share["TARGET-B"]) / 2
    assert abs(s_share["TARGET-C"] - incumbents_mean) <= _MARGIN, (
        f"after C's {_SLOW_START_S}s window elapsed, C took {s_share['TARGET-C']:.3f} vs the "
        f"incumbents' mean {incumbents_mean:.3f} (margin {_MARGIN}); counts={dict(s_counts)!r}; "
        f"ramp timeline={timeline!r}"
    )
    assert s_share["TARGET-C"] > w_share["TARGET-C"] + _MARGIN, (
        f"C's share did not rise across its window: {w_share['TARGET-C']:.3f} in-window vs "
        f"{s_share['TARGET-C']:.3f} after; timeline={timeline!r}"
    )


# Network teardown: load balancers and similar resources delete asynchronously and leave ENIs in
# the subnet or security group, so an immediate delete fails with DependencyViolation. Wait for
# the ENIs (bounded, shared by all of one check's network deletes), then retry within the window.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
