"""lb-cookie-stickiness-pins-a-client-to-one-registered-instance."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lb-cookie-stickiness-pins-a-client-to-one-registered-instance"
GROUP = 'data-plane'
SERVICES = ['elb']

#: Declared deadlines — the names are what earns this check a wrapper larger than the light
#: 300 s one (behavioral_validate._suite_has_slow_checks reads them off the source). Two cold
#: EC2 instances plus a health quorum plus ELB DNS propagation do not fit in 300 s.
_INSERVICE_DEADLINE_S = 480
_HTTP_DEADLINE_S = 360

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
    """Raw HTTP through the load balancer's own DNS name — no SigV4, no AWS SDK."""
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, method=method, headers={**(headers or {}), **route_headers})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")


def _teardown(fn, *gone_codes):
    """Run one teardown call; only the resource's not-found codes count as already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone_codes:
            raise


_ELB_GONE = ("LoadBalancerNotFound", "ListenerNotFound", "PolicyNotFound", "InvalidInstance", "SubnetNotFound",
             "InvalidAssociationID.NotFound")


def _safe(fn):
    """A cleanup step DeleteLoadBalancer also covers: done once the load balancer or the item is gone."""
    return lambda: _teardown(fn, *_ELB_GONE)


def _usable_azs(ctx, want="t3.micro", n=2):
    """AZ names that are BOTH available and really offer `want` — see the note in the sibling
    data-plane check: letting AWS choose the zone is how RunInstances fails 'Unsupported'."""
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert len(usable) >= n, (
        f"{ctx.region} offers {want!r} in available zones {usable!r}; this check needs {n}"
    )
    return usable[:n]


def _public_network(ctx, azs):
    """Own VPC, internet gateway, route to it, and one public subnet per AZ, tagged at
    creation and independent of a default VPC; an internet-facing Classic ELB needs an
    internet-gateway route in every subnet it is attached to."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.84.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": list(_TAGS)}],
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _teardown(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id),
                  "InvalidInternetGatewayID.NotFound")

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _detach_igw():
        _teardown(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id),
                  "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached")

    ctx.on_cleanup(_detach_igw)
    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": list(_TAGS)}],
    )["RouteTable"]["RouteTableId"]

    def _drop_rt():
        _teardown(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id),
                  "InvalidRouteTableID.NotFound")

    ctx.on_cleanup(_drop_rt)
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.84.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": list(_TAGS)}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _drop_subnet(s=subnet_id):
            _teardown(lambda: _delete_net(ec2, "delete_subnet", SubnetId=s), "InvalidSubnetID.NotFound")

        ctx.on_cleanup(_drop_subnet)
        assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(_safe(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnet_ids


def _http_sg(ctx, vpc_id, source, ports=(80,)):
    """A security group admitting tcp *ports* from *source* (IpRanges or UserIdGroupPairs)."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real classic-elb data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        _teardown(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")

    ctx.on_cleanup(_drop_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": p, "ToPort": p, **source,
        } for p in ports],
    )
    return sg_id


def _describe_instance(ctx, ec2, iid):
    """DescribeInstances tolerating the eventual consistency right after RunInstances."""
    deadline = time.monotonic() + 120
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    last = None
    while True:
        try:
            return ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                raise
            last = exc
        except (IndexError, KeyError) as exc:
            last = exc
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance {iid} never appeared in DescribeInstances: {last!r}")
        time.sleep(2)


def _terminate_and_wait(ctx, ec2, ids):
    """Terminate the instances, then wait until each is 'terminated': an instance's ENI holds its
    security group and subnet. NotFound right after RunInstances is eventual consistency."""
    deadline = time.monotonic() + 60
    while True:
        try:
            ec2.terminate_instances(InstanceIds=ids)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidInstanceID.NotFound" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    deadline = time.monotonic() + 180
    pending = set(ids)
    while True:
        pending = {i for i in pending if _describe_instance(ctx, ec2, i)["State"]["Name"] != "terminated"}
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"instances {sorted(pending)} not terminated 180 s after TerminateInstances")
        time.sleep(2)


def _launch_backend(ctx, subnet_id, sg_id, user_data, *, want="t3.micro"):
    """One EC2 instance running an HTTP backend from user-data, tagged AT CREATION. The AMI comes
    from the SSM public parameter: a hardcoded image id is region-specific and goes stale."""
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-behav-ec2-")
    tag_set = list(_TAGS) + [{"Key": "Name", "Value": name}]
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id], UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tag_set},
            {"ResourceType": "volume", "Tags": tag_set},
        ],
    )["Instances"][0]["InstanceId"]

    def _drop_instance():
        _terminate_and_wait(ctx, ec2, [iid])

    ctx.on_cleanup(_drop_instance)
    return iid


def _assert_running(ctx, iid):
    ec2 = ctx.client("ec2")
    _poll_until(
        lambda: _describe_instance(ctx, ec2, iid)["State"]["Name"],
        lambda s: s in ("running", "terminated", "shutting-down"),
        timeout_s=300, interval_s=5,
        description=f"instance {iid} reaching a terminal launch state",
    )
    state = _describe_instance(ctx, ec2, iid)["State"]["Name"]
    assert state == "running", f"instance {iid} state {state!r}, expected running"


def _create_classic_lb(ctx, subnet_ids, sg_id, *, scheme="internet-facing", listeners=None):
    """Billable resource: the waited teardown is registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elb")
    name = ctx.unique_name("sim2real-clb-")  # 25 chars; the API ceiling is 32
    created = _retry_throttled(lambda: elb.create_load_balancer(
        LoadBalancerName=name,
        Listeners=listeners or [{"Protocol": "HTTP", "LoadBalancerPort": 80,
                                 "InstanceProtocol": "HTTP", "InstancePort": 80}],
        Subnets=list(subnet_ids), SecurityGroups=[sg_id], Scheme=scheme,
        Tags=[{"Key": "sim2real", "Value": CHECK[:64]}],
    ))

    def _drop_lb():
        _teardown(lambda: elb.delete_load_balancer(LoadBalancerName=name), "LoadBalancerNotFound")
        # DeleteLoadBalancer returns before the ENIs are released: poll the name out of Describe
        # before the network deletes behind this one run.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.describe_load_balancers(LoadBalancerNames=[name])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"load balancer {name} still described 60 s after DeleteLoadBalancer")
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return name, created["DNSName"]


def _configure_health_check(ctx, lb_name, target, *, interval=5, timeout=2,
                            healthy=2, unhealthy=2):
    return ctx.client("elb").configure_health_check(
        LoadBalancerName=lb_name,
        HealthCheck={"Target": target, "Interval": interval, "Timeout": timeout,
                     "UnhealthyThreshold": unhealthy, "HealthyThreshold": healthy},
    )["HealthCheck"]


def _wait_instance_health(ctx, lb_name, iid, wanted, *, timeout_s=480):
    elb = ctx.client("elb")
    seen = []

    def probe():
        states = elb.describe_instance_health(
            LoadBalancerName=lb_name, Instances=[{"InstanceId": iid}])["InstanceStates"]
        state = states[0] if states else None
        seen.append(None if state is None else f"{state.get('State')}/{state.get('ReasonCode')}")
        return state

    return _poll_until(
        probe, lambda s: s is not None and s.get("State") == wanted,
        timeout_s=timeout_s, interval_s=5,
        description=f"instance {iid} reaching ELB state {wanted!r} (observed: {seen[-10:]})",
    )


def _sample(ctx, url, n, *, headers=None):
    """n sequential GETs; returns the bodies. Every response must be a 200."""
    bodies = []
    for _ in range(n):
        status, hdrs, body = _http(ctx, url, headers=headers)
        assert status == 200, f"GET {url} returned {status}, body={body[:200]!r}"
        bodies.append((body.strip(), hdrs))
    return bodies


def _poll_bodies(ctx, url, predicate, description, *, n=16, timeout_s=300, headers=None):
    seen = []

    def probe():
        try:
            bodies = [b for b, _h in _sample(ctx, url, n, headers=headers)]
        except (AssertionError, urllib.error.URLError, OSError) as exc:
            seen.append(f"<{type(exc).__name__}: {str(exc)[:60]}>")
            return None
        seen.append(sorted(set(bodies)))
        return bodies

    return _poll_until(
        probe, lambda b: b is not None and predicate(b),
        timeout_s=timeout_s, interval_s=5,
        description=f"{description} at {url} (observed: {seen[-6:]})",
    )


def _cookie(headers, name):
    """The value of `name` in a Set-Cookie header, or None. Parsed structurally rather than by
    slicing the raw header: the ELB emits attributes (Expires, Path) after the value."""
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    for morsel in raw.split(","):
        for part in morsel.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
    return None


# ===== end helpers =====


#: Each backend answers with its OWN token, unique to this run, so the body identifies which
#: instance served the request. /ok is the health path.
_USER_DATA_TEMPLATE = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import socketserver

TOKEN = "__TOKEN__"


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = TOKEN.encode()
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
"""


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A duration-based stickiness policy makes the Classic Load Balancer mint an AWSELB cookie and
    pin every request carrying it to one registered instance, while requests without the cookie
    still reach both instances (cross-zone enabled explicitly; it is off by default)."""
    elb = ctx.client("elb")
    azs = _usable_azs(ctx, n=2)
    vpc_id, subnet_ids = _public_network(ctx, azs)
    # The load balancer admits the runner; the backends admit only the load balancer's group.
    sg_id = _http_sg(ctx, vpc_id, {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _http_sg(ctx, vpc_id, {"UserIdGroupPairs": [{"GroupId": sg_id}]})

    tokens = {}
    instance_ids = []
    for subnet_id in subnet_ids:
        token = ctx.unique_name("ELB-BACKEND-")
        iid = _launch_backend(
            ctx, subnet_id, be_sg, _USER_DATA_TEMPLATE.replace("__TOKEN__", token))
        tokens[iid] = token
        instance_ids.append(iid)
    for iid in instance_ids:
        _assert_running(ctx, iid)

    lb_name, dns_name = _create_classic_lb(ctx, subnet_ids, sg_id)
    _configure_health_check(ctx, lb_name, "HTTP:80/ok")
    # Without cross-zone each ELB node serves only its own zone's instances, so one client
    # could never see both tokens.
    elb.modify_load_balancer_attributes(
        LoadBalancerName=lb_name,
        LoadBalancerAttributes={"CrossZoneLoadBalancing": {"Enabled": True}})
    _retry_throttled(lambda: elb.register_instances_with_load_balancer(
        LoadBalancerName=lb_name,
        Instances=[{"InstanceId": i} for i in instance_ids]))
    ctx.on_cleanup(_safe(lambda: elb.deregister_instances_from_load_balancer(
        LoadBalancerName=lb_name, Instances=[{"InstanceId": i} for i in instance_ids])))
    for iid in instance_ids:
        _wait_instance_health(ctx, lb_name, iid, "InService", timeout_s=_INSERVICE_DEADLINE_S)

    url = f"http://{dns_name}/"
    both = set(tokens.values())

    # 1. Baseline, no stickiness policy: a cookie-less client reaches BOTH backends.
    spread = _poll_bodies(ctx,
        url, lambda b: set(b) == both,
        "both registered instances in rotation before any stickiness policy",
        timeout_s=_HTTP_DEADLINE_S)
    assert set(spread) == both, (
        f"before stickiness the load balancer served {sorted(set(spread))!r}, expected both "
        f"backends {sorted(both)!r}"
    )
    no_cookie_headers = _sample(ctx, url, 1)[0][1]
    assert _cookie(no_cookie_headers, "AWSELB") is None, (
        f"the load balancer set an AWSELB cookie with no stickiness policy attached: "
        f"{no_cookie_headers.get('Set-Cookie')!r}"
    )

    # 2. Attach a duration-based stickiness policy — the ONE thing that changes.
    policy = ctx.unique_name("sim2real-sticky-")
    elb.create_lb_cookie_stickiness_policy(
        LoadBalancerName=lb_name, PolicyName=policy, CookieExpirationPeriod=300)
    ctx.on_cleanup(_safe(lambda: elb.delete_load_balancer_policy(
        LoadBalancerName=lb_name, PolicyName=policy)))
    elb.set_load_balancer_policies_of_listener(
        LoadBalancerName=lb_name, LoadBalancerPort=80, PolicyNames=[policy])
    ctx.on_cleanup(_safe(lambda: elb.set_load_balancer_policies_of_listener(
        LoadBalancerName=lb_name, LoadBalancerPort=80, PolicyNames=[])))
    described = ctx.client("elb").describe_load_balancers(
        LoadBalancerNames=[lb_name])["LoadBalancerDescriptions"][0]
    listener_policies = described["ListenerDescriptions"][0]["PolicyNames"]
    assert listener_policies == [policy], (
        f"the listener carries policies {listener_policies!r}, expected exactly [{policy!r}]"
    )

    # 3. THE DATA PLANE: the ELB mints an AWSELB cookie, and it pins the client to one backend.
    def _minted():
        status, hdrs, body = _http(ctx, url)
        if status != 200:
            return None
        value = _cookie(hdrs, "AWSELB")
        return None if value is None else (value, body.strip())

    minted = _poll_until(
        _minted, lambda r: r is not None,
        timeout_s=_HTTP_DEADLINE_S, interval_s=5,
        description="the load balancer minting an AWSELB stickiness cookie",
    )
    cookie_value, first_body = minted
    assert first_body in both, (
        f"the response that minted the cookie came from {first_body!r}, which is neither "
        f"backend token {sorted(both)!r}"
    )
    pinned = [b for b, _h in _sample(ctx, url, 16, headers={"Cookie": f"AWSELB={cookie_value}"})]
    assert set(pinned) == {first_body}, (
        f"16 requests carrying AWSELB={cookie_value!r} were served by {sorted(set(pinned))!r}; a "
        f"duration-based stickiness policy must pin every one of them to {first_body!r}"
    )

    # 4. Positive control in the same file: the pinning is a property of the COOKIE, not of the
    #    load balancer having stopped spreading traffic. A cookie-less client still sees both.
    unpinned = _poll_bodies(ctx,
        url, lambda b: set(b) == both,
        "a cookie-less client still being spread across both backends while the policy is "
        "attached",
        timeout_s=_HTTP_DEADLINE_S)
    assert set(unpinned) == both, (
        f"with the stickiness policy attached a client sending NO cookie was served "
        f"{sorted(set(unpinned))!r}, expected both {sorted(both)!r} — otherwise the pinning "
        f"above is not attributable to the cookie"
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
