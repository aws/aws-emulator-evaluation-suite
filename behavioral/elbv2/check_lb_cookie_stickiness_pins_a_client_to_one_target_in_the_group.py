"""lb-cookie-stickiness-pins-a-client-to-one-target-in-the-group."""
from __future__ import annotations

# With stickiness.type=lb_cookie the ALB mints AWSALB and AWSALBCORS (over this plain-HTTP listener
# AWSALBCORS has SameSite=None without Secure); replaying AWSALB pins one target, and an undecodable
# AWSALB is re-minted ("the load balancer selects a new target and updates the cookie").

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lb-cookie-stickiness-pins-a-client-to-one-target-in-the-group"
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

_CIDR = "10.173.0.0/16"


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


def _http(ctx, url, *, method="GET", headers=None, timeout=20):
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method=method, headers={**(headers or {}), **_route})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


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
    """AZs that are BOTH available and really offer `instance_type`.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state, and
    describe_availability_zones says nothing about instance types. Letting AWS choose is how a
    subnet lands in an AZ that cannot run the type and RunInstances fails 'Unsupported' — an error
    that reads exactly like a fidelity failure.
    """
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
    """One EC2 instance running HTTP backends from user-data, tagged AT CREATION.

    The AMI comes from the SSM public parameter rather than a hardcoded id: an image id is
    region-specific and a stale one fails in a way that reads like a fidelity defect.
    """
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
        # Wait for 'terminated', not just for the API to return: the instance's ENI holds the
        # security group, and an ENI holder is the classic cause of a causeless DependencyViolation
        # on the security-group delete that runs after this one.
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
                  Scheme="internal", Tags=list(_TAGS))
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


def _wait_target_state(ctx, tg_arn, target, wanted, *, timeout_s=420):
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
        timeout_s=timeout_s, interval_s=5,
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


def _cookies(headers):
    """{name: full 'name=value' pair} for every Set-Cookie on a response."""
    out = {}
    for raw in headers.get_all("Set-Cookie") or []:
        pair = raw.split(";", 1)[0]
        out[pair.split("=", 1)[0]] = raw
    return out


def _sample(ctx, url, n, *, headers=None):
    """n requests; return (bodies, last Set-Cookie map). Every request must be a 200."""
    bodies = []
    last = {}
    for i in range(n):
        status, hdrs, body = _http(ctx, url, headers=headers)
        assert status == 200, (
            f"request {i + 1}/{n} to {url} (headers={headers!r}) returned HTTP {status}, expected "
            f"200; body={body[:120]!r}"
        )
        bodies.append(body.strip())
        last = _cookies(hdrs)
    return bodies, last

#: One instance, two labelled backends on two ports, both 200 on every path. Registering the SAME
#: instance twice on two ports gives a target group two independently identifiable targets without a
#: second billable instance.
_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import socketserver
import threading


def make(label):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = label.encode()
            self.send_response(200)
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


b = S(("", 8080), make("TARGET-B"))
threading.Thread(target=b.serve_forever, daemon=True).start()
S(("", 80), make("TARGET-A")).serve_forever()
PYEOF_INNER
nohup python3 /opt/backend.py >/var/log/sim2real-backend.log 2>&1 &
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Target-group lb_cookie stickiness mints an AWSALB cookie whose replay pins a client to one target while
    clients without it reach both; an undecodable cookie is re-minted, and disabling stickiness ends the pinning."""
    elb = ctx.client("elbv2")

    vpc_id, subnets = _own_public_vpc(ctx)
    subnet_ids = [s["id"] for s in subnets]
    # The load balancer admits the caller; the backend admits only the load balancer's group.
    sg_id = _ingress_sg(ctx, vpc_id, (80,), {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _ingress_sg(ctx, vpc_id, (80, 8080), {"UserIdGroupPairs": [{"GroupId": sg_id}]})

    # The ALB and the instance share this group, so the group's own ingress rules are what let the
    # load balancer reach both backend ports.
    iid = _launch_backend(ctx, subnet_ids[0], be_sg, _USER_DATA)

    lb = _create_load_balancer(
        ctx, subnet_ids, Scheme="internet-facing", SecurityGroups=[sg_id])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(
        ctx, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="HTTP", HealthCheckPath="/", HealthCheckPort="traffic-port",
        HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2, Matcher={"HttpCode": "200"},
    )
    tg_arn = tg["TargetGroupArn"]
    target_a = {"Id": iid, "Port": 80}
    target_b = {"Id": iid, "Port": 8080}
    for target in (target_a, target_b):
        _retry_throttled(lambda t=target: elb.register_targets(
            TargetGroupArn=tg_arn, Targets=[t]))
        ctx.on_cleanup(_safe_cleanup(lambda t=target: elb.deregister_targets(
            TargetGroupArn=tg_arn, Targets=[t])))

    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])

    _wait_target_state(ctx, tg_arn, target_a, "healthy")
    _wait_target_state(ctx, tg_arn, target_b, "healthy")
    url = f"http://{lb['DNSName']}/"
    both = {"TARGET-A", "TARGET-B"}

    # ---- leg 1: stickiness off (the default). Both targets, and NO stickiness cookie. -------
    baseline = _poll_until(
        lambda: _sample(ctx, url, 30)[0],
        lambda b: set(b) == both, timeout_s=420, interval_s=10,
        description="both healthy targets being reached with stickiness disabled",
    )
    assert set(baseline) == both, (
        f"with stickiness disabled 30 requests reached {sorted(set(baseline))!r}, expected both "
        f"TARGET-A and TARGET-B"
    )
    _status, hdrs, _body = _http(ctx, url)
    off_cookies = _cookies(hdrs)
    assert "AWSALB" not in off_cookies and "AWSALBCORS" not in off_cookies, (
        f"a stickiness cookie was minted with stickiness DISABLED: {sorted(off_cookies)!r}, "
        f"expected neither AWSALB nor AWSALBCORS"
    )

    # ---- leg 2: enable exactly one thing. --------------------------------------------------
    _set_tg_attributes(ctx, tg_arn, {
        "stickiness.enabled": "true",
        "stickiness.type": "lb_cookie",
        "stickiness.lb_cookie.duration_seconds": "3600",
    })

    def _minted():
        try:
            status, hdrs_now, body_now = _http(ctx, url)
        except (urllib.error.URLError, OSError):
            return None
        if status != 200:
            return None
        got = _cookies(hdrs_now)
        if "AWSALB" not in got:
            return None
        return (got, body_now.strip())

    cookie_map, first_body = _poll_until(
        _minted, lambda r: r is not None, timeout_s=300, interval_s=5,
        description="the load balancer minting an AWSALB duration-based stickiness cookie",
    )
    assert first_body in both, (
        f"the first cookie-bearing response served {first_body!r}, expected one of {sorted(both)!r}"
    )
    assert "AWSALBCORS" in cookie_map, (
        f"only {sorted(cookie_map)!r} was minted; the documented contract is that AWSALBCORS is "
        f"ALWAYS generated alongside AWSALB"
    )
    cors_raw = cookie_map["AWSALBCORS"]
    lowered = cors_raw.lower()
    assert "samesite=none" in lowered, (
        f"AWSALBCORS was minted as {cors_raw!r}; it must carry SameSite=None, which is the entire "
        f"reason the second cookie exists — a same-origin AWSALB alone would be dropped by a "
        f"cross-origin CORS request under a browser's default SameSite policy"
    )
    assert "secure" not in lowered, (
        f"AWSALBCORS was minted as {cors_raw!r} carrying Secure on a plain-HTTP listener; "
        f"AWS omits Secure here (a Secure, SameSite=None cookie would never be replayed back "
        f"by a compliant browser over unencrypted HTTP, so the load balancer does not set it) — "
        f"this assertion is scoped to HTTP; an HTTPS listener is untested"
    )
    awsalb = cookie_map["AWSALB"].split(";", 1)[0]

    # THE PIN: replaying the cookie must land on the same target every time.
    pinned, _ = _sample(ctx, url, 15, headers={"Cookie": awsalb})
    assert set(pinned) == {first_body}, (
        f"replaying the AWSALB cookie served {sorted(set(pinned))!r} over 15 requests, expected "
        f"only {first_body!r} — the cookie encodes the selected target"
    )

    # TWIN CONTROL IN THE SAME INSTANT: without the cookie the spread is unchanged, so the pin
    # above is attributable to the cookie and not to target B having dropped out.
    unpinned = _poll_until(
        lambda: _sample(ctx, url, 30)[0],
        lambda b: set(b) == both, timeout_s=180, interval_s=10,
        description="un-cookied clients still reaching BOTH targets while a cookied client is "
                    "pinned to one",
    )
    assert set(unpinned) == both, (
        f"with stickiness enabled but no cookie presented, 30 requests reached "
        f"{sorted(set(unpinned))!r}, expected both targets — otherwise the pin above proves nothing"
    )

    # ---- leg 3: a cookie that cannot be decoded is RE-MINTED, not refused. -----------------
    tampered = "AWSALB=" + ("sim2real" * 8)
    tam_status, tam_hdrs, tam_body = _http(ctx, url, headers={"Cookie": tampered})
    assert tam_status == 200, (
        f"an undecodable AWSALB cookie produced HTTP {tam_status} (body {tam_body[:120]!r}); the "
        f"documented behaviour is to select a new target, not to refuse the request"
    )
    tam_cookies = _cookies(tam_hdrs)
    assert "AWSALB" in tam_cookies, (
        f"an undecodable AWSALB cookie was not replaced: Set-Cookie carried "
        f"{sorted(tam_cookies)!r}, expected a fresh AWSALB"
    )
    assert tam_cookies["AWSALB"].split(";", 1)[0] != tampered, (
        f"the load balancer echoed the undecodable cookie back unchanged ({tampered!r}); it must "
        f"mint a new one carrying the target it just selected"
    )
    assert tam_body.strip() in both, (
        f"the re-minted request served {tam_body.strip()!r}, expected one of {sorted(both)!r}"
    )

    # ---- leg 4: restore the ONE thing that changed. ----------------------------------------
    _set_tg_attributes(ctx, tg_arn, {"stickiness.enabled": "false"})

    def _no_cookie_and_both():
        bodies, last = _sample(ctx, url, 30)
        if "AWSALB" in last or "AWSALBCORS" in last:
            return None
        return sorted(set(bodies))

    restored = _poll_until(
        _no_cookie_and_both, lambda r: r == sorted(both), timeout_s=300, interval_s=10,
        description="stickiness cookies disappearing and both targets being reached again after "
                    "stickiness.enabled was set back to false",
    )
    assert restored == sorted(both), (
        f"after disabling stickiness 30 requests reached {restored!r} with no stickiness cookie, "
        f"expected {sorted(both)!r} — so the pin was attributable to the attribute alone"
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
