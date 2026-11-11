"""deep-elbv2-2-nlbwire-cross-zone-target-group-override."""
from __future__ import annotations

import socket
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-elbv2-2-nlbwire-cross-zone-target-group-override"
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


def _teardown(fn, *, timeout_s=900, interval_s=10):
    """Delete, retrying while a holder still pins the resource; already-gone is done.

    The NLB's own interfaces keep its subnets, security groups and the internet gateway
    attachment busy for minutes after DeleteLoadBalancer returns, so DependencyViolation is
    retried until it clears. The retry is BOUNDED and re-raises, so a teardown that never
    converges surfaces as a leak instead of hanging or passing silently.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if "NotFound" in code or code == "Gateway.NotAttached":
                return
            if time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _usable_azs(ctx, n, want="t3.micro"):
    """AZs that are available AND offer `want`; both catalogues are needed."""
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(Filters=[
        {"Name": "state", "Values": ["available"]},
        {"Name": "zone-type", "Values": ["availability-zone"]},
    ])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert len(usable) >= n, (
        f"need {n} available AZs offering {want!r} in {ctx.region}, found {usable!r}"
    )
    return usable[:n]


def _build_network(ctx, n_az, ports):
    """A VPC this check owns end to end: IGW, a public route, one subnet per AZ, one SG.

    Nothing ambient is used — no default VPC, subnet or security group — so the check runs
    the same on a fresh account. Teardown is registered right after each create; LIFO order
    deletes SG, subnets, the IGW attachment, the IGW, then the VPC.
    """
    ec2 = ctx.client("ec2")
    azs = _usable_azs(ctx, n_az)
    name = ctx.unique_name("sim2real-behav-vpc-")
    tags_ = list(_TAGS) + [{"Key": "Name", "Value": name}]
    cidr = "10.0.0.0/16"
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tags_}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    def _vpc_state():
        try:
            return ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        except ClientError:
            return None

    _poll_until(_vpc_state, lambda s: s == "available", timeout_s=120, interval_s=3,
                description=f"vpc {vpc_id} available")
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": tags_}])["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _teardown(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _teardown(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)))
    main_rt = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)

    subnets = []
    for i, az in enumerate(azs):
        sub_cidr = f"10.0.{i + 1}.0/24"
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=sub_cidr, AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tags_}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=sid: _teardown(lambda: ec2.delete_subnet(SubnetId=s)))
        subnets.append({"az": az, "id": sid, "cidr": sub_cidr})

    # Instance targets see the client's own address (preserve_client_ip) and the health
    # checks' VPC-internal one, so the backend admits exactly those.
    sg_id = _create_sg(ctx, vpc_id, ports, [*ctx.ingress_cidrs(), cidr])
    return {"vpc_id": vpc_id, "cidr": cidr, "subnets": subnets, "sg_id": sg_id}


def _create_sg(ctx, vpc_id, ports, cidrs):
    """A security group admitting tcp *ports* from each of *cidrs*."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real elbv2 nlb data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _teardown(lambda: ec2.delete_security_group(GroupId=sg_id)))
    if ports:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": p, "ToPort": p,
             "IpRanges": [{"CidrIp": c} for c in cidrs]} for p in ports])
    return sg_id


#: A raw-socket backend. Per connection it reads until the client's " END\n" terminator and
#: answers with what IT observed: the port it accepted on, the peer address of the TCP
#: connection, its own zone marker, the tokens of every earlier payload it received, and the
#: hex of EVERY byte the load balancer handed it — so a PROXY protocol header, if any, is
#: reported verbatim rather than interpreted by the backend.
_BACKEND = r'''
import socket, sys, threading
MARK = sys.argv[1]
PORTS = [int(p) for p in sys.argv[2:]]
END = b" END\n"
HIST = []
LOCK = threading.Lock()


def handle(conn, addr, port):
    try:
        conn.settimeout(5)
        buf = b""
        while END not in buf and len(buf) < 8192:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        if END not in buf:
            return
        i = buf.find(b"PING ")
        token = buf[i + 5:].split(b" ", 1)[0].decode("ascii", "replace") if i >= 0 else "?"
        with LOCK:
            hist = ",".join(HIST[-200:])
            HIST.append(token)
        reply = "PORT=%d PEER=%s:%d MARK=%s HIST=%s HEX=%s\n" % (
            port, addr[0], addr[1], MARK, hist, buf.hex())
        conn.sendall(reply.encode())
    except Exception:
        pass
    finally:
        conn.close()


def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    s.listen(128)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a, port), daemon=True).start()


for p in PORTS[1:]:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
serve(PORTS[0])
'''


def _user_data(marker, ports):
    return (
        "#!/bin/bash\n"
        "cat >/opt/sim2real_backend.py <<'PYEOF_INNER'\n"
        f"{_BACKEND}\n"
        "PYEOF_INNER\n"
        f"nohup python3 /opt/sim2real_backend.py {marker} {' '.join(str(p) for p in ports)} "
        ">/var/log/sim2real-backend.log 2>&1 &\n"
    )


def _describe_instance(ec2, iid, ctx=None):
    """DescribeInstances tolerating the NotFound that can follow RunInstances."""
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
    """One instance running the raw-socket backend, tagged AT CREATION (instance + volume)."""
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-behav-ec2-")
    tags_ = list(_TAGS) + [{"Key": "Name", "Value": name}]
    iid = ec2.run_instances(
        ImageId=ami, InstanceType=want, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id], UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_},
            {"ResourceType": "volume", "Tags": tags_},
        ],
    )["Instances"][0]["InstanceId"]

    def _drop_instance():
        for _ in range(20):
            try:
                ec2.terminate_instances(InstanceIds=[iid])
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                    raise
                time.sleep(3)
        # Wait for 'terminated': the instance ENI holds the security group and the subnet.
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
        timeout_s=300, interval_s=5, description=f"instance {iid} reaching a launch state",
    )
    described = _describe_instance(ec2, iid, ctx)
    assert described["State"]["Name"] == "running", (
        f"instance {iid} state {described['State']['Name']!r}, expected running"
    )
    return {"id": iid, "private_ip": described["PrivateIpAddress"],
            "az": described["Placement"]["AvailabilityZone"]}


def _create_nlb(ctx, subnet_ids, **kwargs):
    """Billable: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    params = dict(
        Name=_clamp_name(ctx.unique_name("sim2real-behav-nlb-")), Subnets=list(subnet_ids),
        Type="network", Scheme="internet-facing", IpAddressType="ipv4", Tags=list(_TAGS),
    )
    params.update(kwargs)
    lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
                return
            raise
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as err:
                if err.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=10, description="load balancer reaching a terminal state",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_tg(ctx, vpc_id, port):
    """A TCP instance target group with fast health checks (still polled, never assumed)."""
    elb = ctx.client("elbv2")
    tg = _retry_throttled(lambda: elb.create_target_group(
        Name=_clamp_name(ctx.unique_name("sim2real-behav-tg-")),
        Protocol="TCP", Port=port, VpcId=vpc_id, TargetType="instance",
        HealthCheckProtocol="TCP", HealthCheckPort="traffic-port",
        HealthCheckIntervalSeconds=10, HealthyThresholdCount=2, UnhealthyThresholdCount=2,
        Tags=list(_TAGS),
    ))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: elb.delete_target_group(TargetGroupArn=arn),
                                     timeout_s=120, interval_s=4))
    return arn


def _tg_attrs(ctx, tg_arn):
    got = ctx.client("elbv2").describe_target_group_attributes(TargetGroupArn=tg_arn)
    return {a["Key"]: a["Value"] for a in got["Attributes"]}


def _set_tg_attrs(ctx, tg_arn, attrs):
    _retry_throttled(lambda: ctx.client("elbv2").modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=[{"Key": k, "Value": v} for k, v in attrs.items()]))


def _lb_attrs(ctx, lb_arn):
    got = ctx.client("elbv2").describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
    return {a["Key"]: a["Value"] for a in got["Attributes"]}


def _create_listener(ctx, lb_arn, port, tg_arn):
    elb = ctx.client("elbv2")
    arn = _retry_throttled(lambda: elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="TCP", Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    ))["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: elb.delete_listener(ListenerArn=arn),
                                     timeout_s=60, interval_s=4))
    return arn


def _register(ctx, tg_arn, instance_ids, port):
    elb = ctx.client("elbv2")
    targets = [{"Id": i, "Port": port} for i in instance_ids]
    _retry_throttled(lambda: elb.register_targets(TargetGroupArn=tg_arn, Targets=targets))
    return targets


def _wait_healthy(ctx, tg_arn, targets, *, timeout_s=600):
    elb = ctx.client("elbv2")
    seen = []

    def probe():
        descs = elb.describe_target_health(TargetGroupArn=tg_arn, Targets=targets)[
            "TargetHealthDescriptions"]
        states = sorted(d["TargetHealth"]["State"] for d in descs)
        seen.append(states)
        return states

    return _poll_until(
        probe, lambda s: len(s) == len(targets) and all(x == "healthy" for x in s),
        timeout_s=timeout_s, interval_s=10,
        description=f"targets {targets!r} healthy (observed: {seen[-5:]!r})",
    )


def _nlb_nodes(ctx, lb_arn, n_expected, *, timeout_s=300):
    """The NLB's OWN interfaces, one per enabled AZ: {az, private_ip, public_ip}.

    The interface description is "ELB net/<name>/<id>", the same handle the shipped
    source-IP check uses. These are the server-minted oracle for every address assertion.
    """
    ec2 = ctx.client("ec2")
    suffix = lb_arn.split(":loadbalancer/", 1)[1]
    assert suffix.startswith("net/"), f"{lb_arn!r} is not a network load balancer"

    def probe():
        nodes, token = [], None
        while True:
            kw = {"Filters": [{"Name": "description", "Values": [f"ELB {suffix}"]}]}
            if token:
                kw["NextToken"] = token
            page = ec2.describe_network_interfaces(**kw)
            for eni in page["NetworkInterfaces"]:
                nodes.append({
                    "az": eni["AvailabilityZone"],
                    "private_ip": eni.get("PrivateIpAddress"),
                    "public_ip": (eni.get("Association") or {}).get("PublicIp"),
                    "subnet": eni["SubnetId"],
                })
            token = page.get("NextToken")
            if not token:
                return nodes

    return _poll_until(
        probe, lambda ns: len(ns) == n_expected and all(n["public_ip"] for n in ns),
        timeout_s=timeout_s, interval_s=5,
        description=f"{n_expected} NLB interfaces with public addresses",
    )


def _resolve_v4(host):
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return set()
    return {i[4][0] for i in infos}


def _wait_dns(host, expected, *, timeout_s=600):
    return _poll_until(lambda: _resolve_v4(host), lambda got: got == set(expected),
                       timeout_s=timeout_s, interval_s=5,
                       description=f"{host} resolving to exactly {sorted(expected)!r}")


def _exchange(ctx, ip, port, payload, timeout=8):
    """One TCP connection: send `payload`, read to EOF. Transport errors propagate."""
    with socket.create_connection(ctx.endpoint_host(ip, port), timeout=timeout) as s:
        s.sendall(payload)
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)


def _parse_reply(raw):
    """Structural parse of the backend's single-line KEY=VALUE report."""
    line = raw.decode("ascii", "replace").strip()
    fields = {}
    for tok in line.split(" "):
        if "=" in tok:
            k, v = tok.split("=", 1)
            fields[k] = v
    return fields


def _wait_reply(ctx, ip, port, payload, *, timeout_s=420):
    """Poll one TCP exchange until the backend answers; 'unconnectable' fails, bounded."""
    seen = []

    def probe():
        try:
            fields = _parse_reply(_exchange(ctx, ip, port, payload))
        except OSError as exc:
            seen.append(f"<{type(exc).__name__}: {exc}>")
            return None
        seen.append(sorted(fields))
        return fields

    return _poll_until(
        probe, lambda f: f is not None and "HEX" in f and "PEER" in f,
        timeout_s=timeout_s, interval_s=5,
        description=f"backend reply via {ip}:{port} (observed: {seen[-6:]!r})",
    )


def _split_peer(peer):
    host, _, port = peer.rpartition(":")
    return host, int(port)


# ===== end helpers =====

#: Connections sampled through one zone's node. 40 independent flow hashes all landing in one
#: zone by chance, if cross-zone were really on with one target per zone, is 2**-40.
_SAMPLES = 40


def _markers_via(ctx, ip, port, nonce, n):
    """`n` fresh TCP connections to one node address; the zone marker each one reached."""
    marks, errors = [], []
    for i in range(n):
        try:
            fields = _parse_reply(_exchange(ctx, ip, port, f"PING {nonce}-{i} END\n".encode()))
        except OSError as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            continue
        marks.append(fields.get("MARK"))
    return marks, errors


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """With cross-zone load balancing OFF on a network load balancer, a connection entering zone
    A's node reaches only zone A's target; the target group's ``load_balancing.cross_zone.enabled``
    = true overrides the load balancer's false and delivers that entry point to either zone's target.
    """
    nonce = uuid.uuid4().hex[:12]
    net = _build_network(ctx, 2, [8080])
    sub_a, sub_b = net["subnets"]
    mark_a, mark_b = f"zA-{nonce}", f"zB-{nonce}"
    inst_a = _launch_backend(ctx, sub_a["id"], net["sg_id"], _user_data(mark_a, [8080]))
    inst_b = _launch_backend(ctx, sub_b["id"], net["sg_id"], _user_data(mark_b, [8080]))
    assert (inst_a["az"], inst_b["az"]) == (sub_a["az"], sub_b["az"]), (
        f"instances landed in {inst_a['az']!r}/{inst_b['az']!r}, subnets are "
        f"{sub_a['az']!r}/{sub_b['az']!r}"
    )

    nlb = _create_nlb(ctx, [sub_a["id"], sub_b["id"]])
    nlb_arn = nlb["LoadBalancerArn"]
    tg = _create_tg(ctx, net["vpc_id"], 8080)
    targets = _register(ctx, tg, [inst_a["id"], inst_b["id"]], 8080)
    _wait_lb_active(ctx, nlb_arn)
    _create_listener(ctx, nlb_arn, 80, tg)

    lb_before = _lb_attrs(ctx, nlb_arn).get("load_balancing.cross_zone.enabled")
    assert lb_before == "false", (
        f"a network load balancer must default load_balancing.cross_zone.enabled to "
        f"'false': {lb_before!r}"
    )
    tg_before = _tg_attrs(ctx, tg).get("load_balancing.cross_zone.enabled")
    assert tg_before == "use_load_balancer_configuration", (
        f"a new target group must default load_balancing.cross_zone.enabled to "
        f"'use_load_balancer_configuration': {tg_before!r}"
    )
    _wait_healthy(ctx, tg, targets)

    nodes = _nlb_nodes(ctx, nlb_arn, 2)
    by_az = {n["az"]: n for n in nodes}
    assert set(by_az) == {sub_a["az"], sub_b["az"]}, (
        f"NLB nodes are in {sorted(by_az)!r}, expected {sub_a['az']!r} and {sub_b['az']!r}"
    )
    resolved = _wait_dns(nlb["DNSName"], {n["public_ip"] for n in nodes})
    ip_a, ip_b = by_az[sub_a["az"]]["public_ip"], by_az[sub_b["az"]]["public_ip"]
    assert {ip_a, ip_b} == resolved, (
        f"getaddrinfo returned {sorted(resolved)!r}, NLB nodes are A={ip_a!r} B={ip_b!r}"
    )

    # Positive controls: each zone's entry point reaches its own zone's target.
    first_b = _wait_reply(ctx, ip_b, 80, f"PING {nonce}-ctl-b END\n".encode())
    assert first_b["MARK"] == mark_b, (
        f"zone B's entry point {ip_b} reached {first_b['MARK']!r}, expected {mark_b!r}"
    )
    first_a = _wait_reply(ctx, ip_a, 80, f"PING {nonce}-ctl-a END\n".encode())
    assert first_a["MARK"] == mark_a, (
        f"zone A's entry point {ip_a} reached {first_a['MARK']!r}, expected {mark_a!r}"
    )

    # ---- cross-zone OFF: zone A's node never leaves zone A ----
    marks, errors = _markers_via(ctx, ip_a, 80, f"{nonce}-off", _SAMPLES)
    assert len(marks) >= _SAMPLES - 2, (
        f"only {len(marks)}/{_SAMPLES} connections via zone A were answered: {errors[-4:]!r}"
    )
    assert set(marks) == {mark_a}, (
        f"with cross-zone off, zone A's entry point {ip_a} reached markers "
        f"{sorted(set(marks), key=str)!r}; expected only {mark_a!r} "
        f"(counts: A={marks.count(mark_a)} B={marks.count(mark_b)})"
    )

    # ---- target-group override: cross-zone ON at the target group only ----
    _set_tg_attrs(ctx, tg, {"load_balancing.cross_zone.enabled": "true"})
    tg_after = _tg_attrs(ctx, tg).get("load_balancing.cross_zone.enabled")
    assert tg_after == "true", f"target-group cross-zone read back {tg_after!r}"
    lb_after = _lb_attrs(ctx, nlb_arn).get("load_balancing.cross_zone.enabled")
    assert lb_after == "false", (
        f"setting the target-group attribute changed the load balancer's own attribute to "
        f"{lb_after!r}; it must stay 'false'"
    )

    seen = []

    def probe():
        got, _errs = _markers_via(ctx, ip_a, 80, f"{nonce}-on-{len(seen)}", 10)
        seen.extend(got)
        return set(seen)

    reached = _poll_until(
        probe, lambda s: mark_b in s and mark_a in s, timeout_s=420, interval_s=5,
        description=f"zone A's entry point {ip_a} reaching zone B's target {mark_b!r} after "
                    f"the target-group override (observed {len(seen)} replies)",
    )
    assert reached <= {mark_a, mark_b}, (
        f"connections via zone A reached an unknown backend: {sorted(reached, key=str)!r}"
    )
    assert _lb_attrs(ctx, nlb_arn).get("load_balancing.cross_zone.enabled") == "false", (
        "the load balancer's cross-zone attribute changed while the override was in effect"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
