"""deep-elbv2-2-nlbwire-proxy-protocol-v2-signature-and-address-block."""
from __future__ import annotations

import ipaddress
import socket
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-elbv2-2-nlbwire-proxy-protocol-v2-signature-and-address-block"
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
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition",
                ctx=None):
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _teardown(fn, *, timeout_s=900, interval_s=10):
    """Delete, retrying DependencyViolation while the NLB's interfaces still pin the resource;
    already gone is done. Bounded and re-raises, so a teardown that never converges is a leak."""
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
    """A VPC this check owns end to end (IGW, public route, one subnet per AZ, one SG), so it runs
    the same on a fresh account. Teardowns are registered after each create and run LIFO."""
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

    _poll_until(_vpc_state, lambda s: s == "available", timeout_s=120, interval_s=1.0,
                description=f"vpc {vpc_id} available", ctx=ctx)
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
    deadline = time.monotonic() + (120 if ctx is None else _budget_s(ctx, 120))
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
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"instance {iid} appearing in DescribeInstances: the run budget "
                           f"ended first; not graded")
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
        last = None
        for _ in range(225):
            try:
                found = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                    raise
                return
            if not found or not found[0].get("Instances"):
                return
            last = found[0]["Instances"][0]["State"]["Name"]
            if last == "terminated":
                return
            time.sleep(2)
        raise RuntimeError(f"instance {iid} was not deleted: {last!r}")

    ctx.on_cleanup(_drop_instance)
    _poll_until(
        lambda: _describe_instance(ec2, iid, ctx)["State"]["Name"],
        lambda s: s in ("running", "terminated", "shutting-down"),
        timeout_s=300, interval_s=2.0, description=f"instance {iid} reaching a launch state",
        ctx=ctx,
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
        last = None
        for _ in range(90):
            try:
                last = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]
            except ClientError as err:
                if err.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)
        raise RuntimeError(f"load balancer {arn} was not deleted: {last!r}")

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=2.0, description="load balancer reaching a terminal state",
        ctx=ctx,
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
        timeout_s=timeout_s, interval_s=1.0, ctx=ctx,
        description=f"targets {targets!r} healthy (observed: {seen[-5:]!r})",
    )


def _nlb_nodes(ctx, lb_arn, n_expected, *, timeout_s=300):
    """The NLB's own interfaces, one per enabled AZ: {az, private_ip, public_ip}, found by their
    description "ELB net/<name>/<id>"; the expected values for every address assertion."""
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
        timeout_s=timeout_s, interval_s=1.0, ctx=ctx,
        description=f"{n_expected} NLB interfaces with public addresses",
    )


def _resolve_v4(ctx, host):
    """The IPv4 addresses ``host`` resolves to via the context's endpoint routing."""
    try:
        infos = socket.getaddrinfo(ctx.endpoint_host(host, 80)[0], None, socket.AF_INET,
                                   socket.SOCK_STREAM)
    except socket.gaierror:
        return set()
    return {i[4][0] for i in infos}


def _wait_dns(ctx, host, expected, *, timeout_s=600):
    return _poll_until(lambda: _resolve_v4(ctx, host), lambda got: got == set(expected),
                       timeout_s=timeout_s, interval_s=1.0, ctx=ctx,
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
        timeout_s=timeout_s, interval_s=1.0, ctx=ctx,
        description=f"backend reply via {ip}:{port} (observed: {seen[-6:]!r})",
    )


def _split_peer(peer):
    host, _, port = peer.rpartition(":")
    return host, int(port)


#: The PROXY protocol v2 signature, byte for byte (haproxy proxy-protocol.txt section 2.2).
_PP2_SIGNATURE = bytes.fromhex("0d0a0d0a000d0a515549540a")


def _decode_pp2(raw):
    """Decode a PPv2 header structurally: signature, ver/cmd, family, length, IPv4 block, TLVs."""
    assert len(raw) >= 28, f"only {len(raw)} bytes reached the backend: {raw.hex()!r}"
    length = int.from_bytes(raw[14:16], "big")
    end = 16 + length
    assert len(raw) >= end, (
        f"PPv2 header declares {length} address bytes but only {len(raw) - 16} followed: "
        f"{raw.hex()!r}"
    )
    tlvs, pos = [], 28
    while pos < end:
        assert pos + 3 <= end, f"truncated TLV at offset {pos} in {raw[:end].hex()!r}"
        t_len = int.from_bytes(raw[pos + 1:pos + 3], "big")
        assert pos + 3 + t_len <= end, (
            f"TLV type 0x{raw[pos]:02x} at offset {pos} overruns the header: {raw[:end].hex()!r}"
        )
        tlvs.append((raw[pos], raw[pos + 3:pos + 3 + t_len], pos + 3))
        pos += 3 + t_len
    return {
        "header": raw[:end],
        "signature": raw[:12], "ver_cmd": raw[12], "family": raw[13], "length": length,
        "src_ip": str(ipaddress.IPv4Address(raw[16:20])),
        "dst_ip": str(ipaddress.IPv4Address(raw[20:24])),
        "src_port": int.from_bytes(raw[24:26], "big"),
        "dst_port": int.from_bytes(raw[26:28], "big"),
        "tlvs": tlvs, "payload": raw[end:],
    }


def _crc32c(data):
    """CRC-32C (Castagnoli), reflected polynomial 0x82F63B78 — PPv2's PP2_TYPE_CRC32C."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


_PP2_TYPE_CRC32C = 0x03


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """With proxy_protocol_v2.enabled, the backend receives the PPv2 signature, a PROXY/TCP4 header
    naming the real client, the NLB node's private address and listener port and a valid CRC32C
    TLV, then the payload unmodified; an otherwise identical target group delivers no header.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/network/edit-target-group-attributes.html"""
    nonce = uuid.uuid4().hex[:12]
    net = _build_network(ctx, 1, [8080, 8081])
    sub = net["subnets"][0]
    inst = _launch_backend(ctx, sub["id"], net["sg_id"], _user_data(f"pp-{nonce}", [8080, 8081]))

    nlb = _create_nlb(ctx, [sub["id"]])
    nlb_arn = nlb["LoadBalancerArn"]
    tg_pp = _create_tg(ctx, net["vpc_id"], 8080)
    tg_plain = _create_tg(ctx, net["vpc_id"], 8081)

    plain_attrs = _tg_attrs(ctx, tg_plain)
    assert plain_attrs.get("proxy_protocol_v2.enabled") == "false", (
        f"a new TCP target group must default proxy_protocol_v2.enabled to 'false': "
        f"{plain_attrs.get('proxy_protocol_v2.enabled')!r}"
    )
    _set_tg_attrs(ctx, tg_pp, {"proxy_protocol_v2.enabled": "true"})
    pp_attrs = _tg_attrs(ctx, tg_pp)
    assert pp_attrs.get("proxy_protocol_v2.enabled") == "true", (
        f"proxy_protocol_v2.enabled did not read back 'true': "
        f"{pp_attrs.get('proxy_protocol_v2.enabled')!r}"
    )

    pp_targets = _register(ctx, tg_pp, [inst["id"]], 8080)
    plain_targets = _register(ctx, tg_plain, [inst["id"]], 8081)
    _wait_lb_active(ctx, nlb_arn)
    _create_listener(ctx, nlb_arn, 80, tg_pp)
    _create_listener(ctx, nlb_arn, 81, tg_plain)
    _wait_healthy(ctx, tg_pp, pp_targets)
    _wait_healthy(ctx, tg_plain, plain_targets)

    nodes = _nlb_nodes(ctx, nlb_arn, 1)
    node = nodes[0]
    _wait_dns(ctx, nlb["DNSName"], {ctx.endpoint_host(node["public_ip"], 80)[0]})
    entry_ip = node["public_ip"]

    # ---- PROXY protocol ON: listener 80 -> target group with the attribute ----
    payload = f"PING {nonce}-pp END\n".encode()
    pp = _wait_reply(ctx, entry_ip, 80, payload)
    raw = bytes.fromhex(pp["HEX"])
    assert raw[:12] == _PP2_SIGNATURE, (
        f"the first 12 bytes the backend received were {raw[:12].hex()!r}, not the PPv2 "
        f"signature {_PP2_SIGNATURE.hex()!r}; full stream {raw.hex()!r}"
    )
    hdr = _decode_pp2(raw)
    assert hdr["ver_cmd"] == 0x21, (
        f"PPv2 version/command byte is 0x{hdr['ver_cmd']:02x}, expected 0x21 (v2, PROXY)"
    )
    assert hdr["family"] == 0x11, (
        f"PPv2 family/protocol byte is 0x{hdr['family']:02x}, expected 0x11 (TCP over IPv4)"
    )
    assert hdr["payload"] == payload, (
        f"the client payload did not follow the header unmodified: {hdr['payload']!r} "
        f"vs sent {payload!r}"
    )
    peer_ip, peer_port = _split_peer(pp["PEER"])
    assert (hdr["src_ip"], hdr["src_port"]) == (peer_ip, peer_port), (
        f"the PPv2 source {hdr['src_ip']}:{hdr['src_port']} is not the connection's own peer "
        f"{peer_ip}:{peer_port} as the backend socket observed it"
    )
    src = ipaddress.ip_address(hdr["src_ip"])
    assert src.is_global and src not in ipaddress.ip_network(net["cidr"]), (
        f"the PPv2 source address {hdr['src_ip']!r} is not the external client: it is "
        f"non-global or inside the VPC {net['cidr']!r}"
    )
    assert hdr["dst_port"] == 80, (
        f"the PPv2 destination port is {hdr['dst_port']!r}, not the listener port 80"
    )
    # The destination is the NLB node's private interface address, not the public one dialled.
    assert hdr["dst_ip"] == node["private_ip"], (
        f"the PPv2 destination {hdr['dst_ip']!r} is not the NLB node's private interface "
        f"address {node['private_ip']!r} (public {node['public_ip']!r})"
    )
    # The header carries a PP2_TYPE_CRC32C TLV checksumming the whole header with its own value
    # zeroed (haproxy proxy-protocol.txt section 2.2.5).
    crcs = [t for t in hdr["tlvs"] if t[0] == _PP2_TYPE_CRC32C]
    assert len(crcs) == 1 and len(crcs[0][1]) == 4, (
        f"expected exactly one 4-byte CRC32C TLV, TLVs were "
        f"{[(hex(t), v.hex()) for t, v, _o in hdr['tlvs']]!r}"
    )
    _t, crc_value, crc_off = crcs[0]
    zeroed = bytearray(hdr["header"])
    zeroed[crc_off:crc_off + 4] = b"\x00\x00\x00\x00"
    computed = _crc32c(bytes(zeroed))
    assert computed == int.from_bytes(crc_value, "big"), (
        f"the CRC32C TLV {crc_value.hex()!r} does not match the header's checksum "
        f"{computed:08x}; header {hdr['header'].hex()!r}"
    )
    assert pp["PORT"] == "8080", f"the PROXY arm landed on backend port {pp['PORT']!r}"

    # ---- PROXY protocol OFF: listener 81 -> identical target group without it ----
    plain_payload = f"PING {nonce}-plain END\n".encode()
    plain = _wait_reply(ctx, entry_ip, 81, plain_payload)
    plain_raw = bytes.fromhex(plain["HEX"])
    assert plain_raw == plain_payload, (
        f"with proxy_protocol_v2 off the backend must receive exactly the client's bytes; "
        f"got {plain_raw.hex()!r} for sent {plain_payload.hex()!r}"
    )
    assert _PP2_SIGNATURE not in plain_raw, (
        f"a PPv2 signature appeared on the attribute-off path: {plain_raw.hex()!r}"
    )
    assert plain["PORT"] == "8081", f"the control arm landed on backend port {plain['PORT']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
