"""elbv2shape-deep-elbv2-3-app-cookie-stickiness-pins-with-cookie-spreads-without."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "elbv2shape-deep-elbv2-3-app-cookie-stickiness-pins-with-cookie-spreads-without"
GROUP = "data-plane"
SERVICES = ["elbv2"]

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


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


def _safe_cleanup(fn):
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s, anything else raises."""
    def _wrapped():
        deadline = time.monotonic() + 180.0
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _GONE:
                    return
                if code not in _IN_USE or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

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
        # _delete_net retries DependencyViolation while ENIs release; an already-deleted group is gone.
        try:
            _delete_net(ec2, "delete_security_group", GroupId=sg_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidGroup.NotFound":
                raise

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


def _describe_instance(ec2, iid):
    """DescribeInstances tolerating the eventual consistency right after RunInstances."""
    last = None
    deadline = time.monotonic() + 120.0
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


def _instance_terminated(ec2, iid) -> bool:
    """Whether the instance is terminated; an instance AWS no longer lists counts as terminated."""
    try:
        found = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
            return True
        raise
    return not found or found[0]["Instances"][0]["State"]["Name"] == "terminated"


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
        # Wait for 'terminated': the instance's ENI holds the security group, and an ENI holder
        # is the classic cause of a DependencyViolation on the security-group delete after this.
        deadline = time.monotonic() + 300.0
        while not _instance_terminated(ec2, iid):
            if time.monotonic() >= deadline:
                raise AssertionError(f"instance {iid} not terminated after 300 s of teardown")
            time.sleep(5)

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
        # A target group stays ResourceInUse until the listener or rule forwarding to it is gone.
        deadline = time.monotonic() + 40.0
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceInUse" or time.monotonic() >= deadline:
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

_APP_COOKIE = "SIMAPPSESSION"
_REMOVE = "_remove_"
_BOTH = {"TARGET-A", "TARGET-B"}


def _cookies(headers):
    """{name: 'name=value'} for every Set-Cookie on a response."""
    out = {}
    for raw in headers.get_all("Set-Cookie") or []:
        pair = raw.split(";", 1)[0].strip()
        out[pair.split("=", 1)[0]] = pair
    return out


def _seq(ctx, url, n, *, headers=None):
    """n sequential requests; every one must be 200. -> (bodies, per-response cookie maps)."""
    bodies, cookies = [], []
    for i in range(n):
        status, hdrs, body = _http(ctx, url, headers=headers)
        assert status == 200, (
            f"request {i + 1}/{n} to {url} (headers={headers!r}) returned {status}: {body[:120]!r}"
        )
        bodies.append(body.strip())
        cookies.append(_cookies(hdrs))
    return bodies, cookies


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """Application-cookie stickiness pins a client presenting the named cookie with its AWSALBAPP companion to the
    minting target, neither cookie alone pins, and clients without cookies keep reaching both targets."""
    elb = ctx.client("elbv2")

    vpc_id, subnets = _own_public_vpc(ctx, cidr="10.177.0.0/16")
    subnet_ids = [s["id"] for s in subnets]
    # The load balancer admits the caller; the backend admits only the load balancer's group.
    sg_id = _ingress_sg(ctx, vpc_id, (80,), {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _ingress_sg(ctx, vpc_id, (80, 8080), {"UserIdGroupPairs": [{"GroupId": sg_id}]})
    config = {"80": {"label": "TARGET-A", "cookie": _APP_COOKIE},
              "8080": {"label": "TARGET-B", "cookie": _APP_COOKIE}}
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
    _set_tg_attributes(ctx, tg_arn, {
        "stickiness.enabled": "true",
        "stickiness.type": "app_cookie",
        "stickiness.app_cookie.cookie_name": _APP_COOKIE,
        "stickiness.app_cookie.duration_seconds": "3600",
    })
    targets = [{"Id": iid, "Port": 80}, {"Id": iid, "Port": 8080}]
    _retry_throttled(lambda: elb.register_targets(TargetGroupArn=tg_arn, Targets=targets))
    ctx.on_cleanup(_safe_cleanup(lambda: elb.deregister_targets(
        TargetGroupArn=tg_arn, Targets=targets)))
    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])
    for t in targets:
        _wait_target_state(ctx, tg_arn, t, "healthy")
    base = f"http://{lb['DNSName']}"
    _wait_serving(ctx, f"{base}/nc/ping")

    # ---- leg 1: the target sets no app cookie -> nothing to stick to. -----------------------
    nc_bodies, nc_cookies = _poll_until(
        lambda: _seq(ctx, f"{base}/nc/x", 30), lambda r: set(r[0]) == _BOTH,
        timeout_s=300, interval_s=10,
        description="both targets reached by uncookied requests whose target sets no app cookie",
    )
    # The load balancer still sends AWSALBAPP-0..3, but every one is the clearing
    # value `_remove_` — no target is encoded until the application sets its cookie.
    encoded_without_app = sorted({v for m in nc_cookies for k, v in m.items()
                                  if k.startswith("AWSALBAPP") and v != f"{k}={_REMOVE}"})
    assert not encoded_without_app, (
        f"responses whose target set no {_APP_COOKIE!r} cookie carried target-encoding "
        f"AWSALBAPP cookies {encoded_without_app[:2]!r}; with no application cookie there must be "
        f"nothing to stick to (every AWSALBAPP-* is {_REMOVE!r})"
    )

    # ---- leg 2: the target sets the app cookie -> AWSALBAPP-* is minted. --------------------
    bodies, cookie_maps = _seq(ctx, f"{base}/x", 30)
    assert set(bodies) == _BOTH, (
        f"uncookied requests reached {sorted(set(bodies))!r}, expected both targets — without "
        f"the cookie stickiness must not pin anyone"
    )
    first_body, first = bodies[0], cookie_maps[0]
    assert _APP_COOKIE in first, (
        f"the target's own {_APP_COOKIE!r} cookie did not reach the client: {sorted(first)!r}"
    )
    alb_names = sorted(k for k in first if k.startswith("AWSALBAPP-")
                       and first[k] != f"{k}={_REMOVE}")
    assert alb_names, (
        f"no target-encoding AWSALBAPP-* cookie was minted alongside the application cookie; "
        f"Set-Cookie carried {first!r}"
    )
    alb_pairs = "; ".join(first[k] for k in alb_names)
    cookie_header = "; ".join([first[_APP_COOKIE], alb_pairs])

    # ---- leg 3: present the cookie -> pinned. -----------------------------------------------
    pinned, _ = _seq(ctx, f"{base}/x", 20, headers={"Cookie": cookie_header})
    assert set(pinned) == {first_body}, (
        f"presenting {cookie_header[:120]!r} served {Counter(pinned)!r} over 20 requests, "
        f"expected only {first_body!r} — the target that minted the cookie"
    )

    # ---- leg 3b: the load balancer's cookie WITHOUT the named app cookie does not pin. -----
    # Stickiness is conditional on the application cookie being present in the
    # request; AWSALBAPP alone is ignored and the request is load-balanced normally.
    alb_only = _poll_until(
        lambda: _seq(ctx, f"{base}/x", 30, headers={"Cookie": alb_pairs})[0],
        lambda b: set(b) == _BOTH, timeout_s=120, interval_s=5,
        description="AWSALBAPP presented WITHOUT the app cookie being load-balanced to both",
    )
    assert set(alb_only) == _BOTH, (
        f"AWSALBAPP without {_APP_COOKIE!r} served {Counter(alb_only)!r}; expected both targets"
    )

    # ---- leg 3c: the app cookie alone does not pin either — the target is encoded in
    # AWSALBAPP, not read from the application's cookie value. ------------------------------
    app_only = _poll_until(
        lambda: _seq(ctx, f"{base}/x", 30, headers={"Cookie": first[_APP_COOKIE]})[0],
        lambda b: set(b) == _BOTH, timeout_s=120, interval_s=5,
        description="the app cookie presented WITHOUT AWSALBAPP being load-balanced to both",
    )
    assert set(app_only) == _BOTH, (
        f"{first[_APP_COOKIE]!r} alone served {Counter(app_only)!r}; expected both targets"
    )

    # The pin is still in force after those (stickiness was not consumed or reset).
    repinned, _ = _seq(ctx, f"{base}/x", 10, headers={"Cookie": cookie_header})
    assert set(repinned) == {first_body}, (
        f"re-presenting both cookies served {Counter(repinned)!r}, expected only {first_body!r}"
    )

    # ---- leg 4: twin control in the same instant — no cookie, still spread. -----------------
    spread, _ = _seq(ctx, f"{base}/x", 30)
    assert set(spread) == _BOTH, (
        f"while a cookied client is pinned, uncookied requests reached {Counter(spread)!r}, "
        f"expected both targets — otherwise the pin above is not attributable to the cookie"
    )


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
