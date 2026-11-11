"""cross-zone-load-balancing-spreads-requests-beyond-the-node-zone."""
from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-zone-load-balancing-spreads-requests-beyond-the-node-zone"
GROUP = 'data-plane'
SERVICES = ['elb']

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _clamp_name(name, maxlen=32):
    """Classic ELB names are <=32 chars and may not end in a hyphen."""
    return name[:maxlen].rstrip("-")


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


class _Succeeded(Exception):
    """A call that real AWS rejects returned successfully."""


def _error_code(fn):
    """The exact AWS error code `fn` raises; raises if the call succeeds, so accepting
    input AWS rejects is reported as such rather than as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise _Succeeded("call succeeded; real AWS rejects it")


def _http(url, *, method="GET", headers=None, timeout=20):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read().decode("utf-8", "replace")


def _usable_azs(ctx, want="t3.micro", n=2):
    """AZ names that are BOTH available and really offer `want`.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state,
    and describe_availability_zones says nothing about instance types. Letting AWS choose the AZ
    is how a subnet lands in a zone that cannot run the instance type, and the follow-up
    RunInstances fails 'Unsupported' — an error that reads exactly like a fidelity failure.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert len(usable) >= n, (
        f"{ctx.region} offers {want!r} in available AZs {usable!r}; this check needs {n}"
    )
    return usable[:n]


def _vpc_estate(ctx, n_azs=2, port=80):
    """A self-contained public VPC: IGW, a default route, one subnet per usable AZ, and the
    load balancer's and backends' security groups; it does not depend on a default VPC."""
    ec2 = ctx.client("ec2")
    azs = _usable_azs(ctx, n=n_azs)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.180.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": list(_TAGS)}],
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _teardown(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id),
                  "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached")
        _teardown(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id),
                  "InvalidInternetGatewayID.NotFound")

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    # The VPC's main route table is deleted with the VPC, so only the route itself is added.
    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(azs):
        sub_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.180.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": list(_TAGS)}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sub_id)

        def _drop_subnet(sid=sub_id):
            _teardown(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound")

        ctx.on_cleanup(_drop_subnet)

    def _sg(description, source):
        sg_id = ec2.create_security_group(
            GroupName=ctx.unique_name("sim2real-behav-sg-"),
            Description=description,
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
        )["GroupId"]

        def _drop_sg():
            _teardown(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")

        ctx.on_cleanup(_drop_sg)
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, **source}],
        )
        return sg_id

    # The load balancer admits the caller; the backends admit only the load balancer's group.
    sg_id = _sg("sim2real classic-elb data-plane ingress",
                {"IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]})
    be_sg = _sg("sim2real classic-elb backend ingress from the load balancer",
                {"UserIdGroupPairs": [{"GroupId": sg_id}]})
    return vpc_id, subnet_ids, sg_id, be_sg


def _describe_instance(ctx, ec2, iid):
    """DescribeInstances tolerating the eventual consistency right after RunInstances.

    Real AWS returns InvalidInstanceID.NotFound for an instance id RunInstances has just handed
    back, which reads exactly like a fidelity failure if it is not absorbed here.
    """
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


def _launch_backends(ctx, subnet_ids, sg_id, user_datas, *, want="t3.micro"):
    """One EC2 HTTP backend per user-data string, tagged at creation, under one
    teardown registered before the first launch; the AMI comes from the public SSM parameter."""
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    launched = []

    def _drop_instances():
        if launched:
            _terminate_and_wait(ctx, ec2, [i["id"] for i in launched])

    ctx.on_cleanup(_drop_instances)

    for i, user_data in enumerate(user_datas):
        name = ctx.unique_name("sim2real-behav-ec2-")
        tags = list(_TAGS) + [{"Key": "Name", "Value": name}]
        inst = ec2.run_instances(
            ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1,
            SubnetId=subnet_ids[i % len(subnet_ids)], SecurityGroupIds=[sg_id],
            UserData=user_data,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": tags},
                {"ResourceType": "volume", "Tags": tags},
            ],
        )["Instances"][0]
        launched.append({"id": inst["InstanceId"]})

    for entry in launched:
        _poll_until(
            lambda iid=entry["id"]: _describe_instance(ctx, ec2, iid)["State"]["Name"],
            lambda s: s in ("running", "terminated", "shutting-down"),
            timeout_s=420, interval_s=5,
            description=f"instance {entry['id']} reaching a terminal launch state",
        )
        described = _describe_instance(ctx, ec2, entry["id"])
        assert described["State"]["Name"] == "running", (
            f"instance {entry['id']} state {described['State']['Name']!r}, expected running"
        )
        entry["private_ip"] = described["PrivateIpAddress"]
    return launched


def _create_clb(ctx, subnet_ids, sg_id, listeners=None, **kwargs):
    """An internet-facing Classic ELB whose teardown, registered at creation, deletes it
    and waits until it is gone."""
    elb = ctx.client("elb")
    name = _clamp_name(kwargs.pop("LoadBalancerName", None)
                       or ctx.unique_name("sim2real-behav-clb-"))
    params = dict(
        LoadBalancerName=name,
        Listeners=listeners or [{
            "Protocol": "HTTP", "LoadBalancerPort": 80,
            "InstanceProtocol": "HTTP", "InstancePort": 80,
        }],
        Subnets=list(subnet_ids), SecurityGroups=[sg_id],
        Scheme="internet-facing", Tags=list(_TAGS),
    )
    params.update(kwargs)
    created = _retry_throttled(lambda: elb.create_load_balancer(**params))

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
    return {"name": name, "dns": created["DNSName"]}


def _instance_state(ctx, lb_name, iid):
    """One instance's entry in DescribeInstanceHealth, or None if absent."""
    states = ctx.client("elb").describe_instance_health(
        LoadBalancerName=lb_name, Instances=[{"InstanceId": iid}])["InstanceStates"]
    for st in states:
        if st["InstanceId"] == iid:
            return st
    return None


def _wait_instance_state(ctx, lb_name, iid, wanted, *, timeout_s=420):
    seen = []

    def probe():
        st = _instance_state(ctx, lb_name, iid)
        seen.append(None if st is None else f"{st.get('State')}/{st.get('ReasonCode')}")
        return st

    return _poll_until(
        probe, lambda s: s is not None and s.get("State") == wanted,
        timeout_s=timeout_s, interval_s=5,
        description=f"instance {iid} behind {lb_name} reaching {wanted!r} "
                    f"(observed: {seen[-10:]})",
    )


def _sample_bodies(url, n, *, headers=None):
    bodies = []
    for _ in range(n):
        status, _hdrs, body = _http(url, headers=headers)
        assert status == 200, f"GET {url}: HTTP {status}, body={body[:200]!r}"
        bodies.append(body.strip())
    return bodies


def _poll_bodies(url, predicate, description, *, n=20, timeout_s=300, headers=None):
    """Poll a real HTTP request through the load balancer until `predicate` holds.

    A control-plane change reaches the data plane asynchronously, so every leg polls the request
    rather than asserting once; the poll is BOUNDED so a load balancer that never changes
    behaviour fails rather than hangs.
    """
    seen = []

    def probe():
        try:
            bodies = _sample_bodies(url, n, headers=headers)
        except (AssertionError, urllib.error.URLError, OSError) as exc:
            seen.append(f"<{type(exc).__name__}: {str(exc)[:60]}>")
            return None
        seen.append(sorted(set(bodies)))
        return bodies

    return _poll_until(
        probe, lambda b: b is not None and predicate(b),
        timeout_s=timeout_s, interval_s=5,
        description=f"{description} (observed: {seen[-6:]})",
    )


def _fast_health_check(target):
    """The tightest health check Classic ELB accepts, so a transition is seconds not minutes.

    Timeout must be strictly less than Interval, and both thresholds have a floor of 2.
    """
    return {"Target": target, "Interval": 5, "Timeout": 2,
            "UnhealthyThreshold": 2, "HealthyThreshold": 2}


#: Each backend serves its own label at every path EXCEPT those under `deny_paths`, where it
#: answers 404. Pointing the load balancer's single health-check Target at a path only ONE
#: instance 404s is what lets an LB-wide health check mark exactly one instance OutOfService —
#: Classic ELB has no per-instance health configuration, so the divergence has to live in the
#: backends, and a path they BOTH deny is what reaches the every-instance-unhealthy boundary.
_BACKEND_USER_DATA = """#!/bin/bash
cat >/opt/backend.py <<'PYEOF_INNER'
import http.server
import socketserver

LABEL = {label!r}
DENY = {deny!r}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        if any(path.startswith(p) for p in DENY):
            body, code = b"NOT-FOUND", 404
        else:
            body, code = LABEL.encode(), 200
        self.send_response(code)
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


def _backend_user_data(label, deny_paths):
    return _BACKEND_USER_DATA.format(label=label, deny=list(deny_paths))


# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """With cross-zone load balancing off, one load-balancer node address serves only its own zone's
    instance; switching the attribute on makes the same node serve both zones' instances, which
    only a pinned node address (not the DNS name) can show."""
    elb = ctx.client("elb")
    ec2 = ctx.client("ec2")
    marker_a = ctx.unique_name("ELB-ZA-")
    marker_b = ctx.unique_name("ELB-ZB-")
    vpc_id, subnet_ids, sg_id, be_sg = _vpc_estate(ctx, n_azs=2)
    az_of = {s["SubnetId"]: s["AvailabilityZone"]
             for s in ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]}
    assert az_of[subnet_ids[0]] != az_of[subnet_ids[1]], (
        f"both estate subnets are in {az_of[subnet_ids[0]]!r}; this check needs two zones"
    )

    # One backend per zone: that separation is the whole subject of the check.
    backends = _launch_backends(ctx, [subnet_ids[0], subnet_ids[1]], be_sg, [
        _backend_user_data(marker_a, ["/never-a"]),
        _backend_user_data(marker_b, ["/never-b"]),
    ])
    iid_a, iid_b = backends[0]["id"], backends[1]["id"]

    lb = _create_clb(ctx, subnet_ids, sg_id)
    elb.configure_health_check(
        LoadBalancerName=lb["name"], HealthCheck=_fast_health_check("HTTP:80/ping"))
    _retry_throttled(lambda: elb.register_instances_with_load_balancer(
        LoadBalancerName=lb["name"],
        Instances=[{"InstanceId": iid_a}, {"InstanceId": iid_b}]))
    ctx.on_cleanup(_safe(lambda: elb.deregister_instances_from_load_balancer(
        LoadBalancerName=lb["name"],
        Instances=[{"InstanceId": iid_a}, {"InstanceId": iid_b}])))
    _wait_instance_state(ctx, lb["name"], iid_a, "InService")
    _wait_instance_state(ctx, lb["name"], iid_b, "InService")

    off = elb.describe_load_balancer_attributes(
        LoadBalancerName=lb["name"])["LoadBalancerAttributes"]["CrossZoneLoadBalancing"]
    assert off["Enabled"] is False, (
        f"a newly created Classic ELB reported CrossZoneLoadBalancing {off!r}; this check's "
        f"first leg requires it to start disabled"
    )

    # Pin the node addresses the DNS name resolves to. Resolution is retried because the records
    # for a freshly created balancer appear a little after CreateLoadBalancer returns.
    def _nodes():
        try:
            infos = socket.getaddrinfo(lb["dns"], 80, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        return sorted({info[4][0] for info in infos})

    node_ips = _poll_until(
        _nodes, lambda ips: len(ips) >= 1, timeout_s=300, interval_s=5,
        description=f"the load balancer DNS name {lb['dns']!r} resolving to a node address")
    assert node_ips, f"{lb['dns']!r} resolved to no addresses"

    # 1. Cross-zone OFF: each pinned node serves exactly ONE marker — its own zone's instance.
    per_node_off = {}
    for ip in node_ips:
        bodies = _poll_bodies(
            f"http://{ip}/", lambda b: len(set(b)) == 1,
            f"node {ip} serving a single zone's instance with cross-zone disabled", n=12)
        per_node_off[ip] = set(bodies)
    for ip, served in per_node_off.items():
        assert len(served) == 1, (
            f"with cross-zone load balancing disabled node {ip} served {sorted(served)!r}; a "
            f"node must reach only the instances in its OWN availability zone"
        )
        assert served <= {marker_a, marker_b}, (
            f"node {ip} served {sorted(served)!r}, which is neither registered backend"
        )

    # 2. Change exactly one thing.
    elb.modify_load_balancer_attributes(
        LoadBalancerName=lb["name"],
        LoadBalancerAttributes={"CrossZoneLoadBalancing": {"Enabled": True}})
    on = elb.describe_load_balancer_attributes(
        LoadBalancerName=lb["name"])["LoadBalancerAttributes"]["CrossZoneLoadBalancing"]
    assert on["Enabled"] is True, (
        f"CrossZoneLoadBalancing read back {on!r} after being enabled"
    )

    # 3. The same pinned nodes now reach BOTH zones' instances.
    for ip in node_ips:
        bodies = _poll_bodies(
            f"http://{ip}/", lambda b: set(b) == {marker_a, marker_b},
            f"node {ip} reaching both zones' instances once cross-zone is enabled", n=12)
        assert set(bodies) == {marker_a, marker_b}, (
            f"with cross-zone load balancing enabled node {ip} served {sorted(set(bodies))!r}, "
            f"expected both {marker_a!r} and {marker_b!r} — the attribute changed nothing in "
            f"the data plane. Before the change this node served "
            f"{sorted(per_node_off[ip])!r}"
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
