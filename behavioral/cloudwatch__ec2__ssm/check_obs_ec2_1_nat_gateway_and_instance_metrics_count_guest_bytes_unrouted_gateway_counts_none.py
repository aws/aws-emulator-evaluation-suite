"""obs-ec2-1-nat-gateway-and-instance-metrics-count-guest-bytes-unrouted-gateway-counts-none."""
from __future__ import annotations

import datetime
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-ec2-1-nat-gateway-and-instance-metrics-count-guest-bytes-unrouted-gateway-counts-none"
GROUP = "nat-gateway-metrics"
SERVICES = ["cloudwatch", "ec2", "ssm"]

_VPC_CIDR = "10.73.0.0/16"
_PUBLIC_A_CIDR = "10.73.0.0/24"
_PUBLIC_B_CIDR = "10.73.1.0/24"
_PRIVATE_CIDR = "10.73.10.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_SSM_ONLINE_TIMEOUT_S = 600
_PHASE_TIMEOUT_S = 420
#: The known byte count the private guest sends over ONE TCP connection. 32 MiB is far above
#: anything the SSM agent's own control traffic moves through the gateway in the window, so a
#: metric that did not count the transfer cannot reach the bound on background traffic alone.
_PAYLOAD_BYTES = 32 * 1024 * 1024
#: The largest frame an EC2 network interface transmits (the VPC jumbo MTU). N bytes cannot leave
#: the instance in fewer than ceil(N / 9001) packets, so this lower bound on NetworkPacketsOut holds
#: on any path; through an internet gateway the real count is several times higher.
_MAX_FRAME_BYTES = 9001
_SINK_PORT = 5201
#: How long the sender keeps the connection open after its last byte, so the connection is ACTIVE
#: across at least one whole one-minute ActiveConnectionCount sample.
_HOLD_OPEN_S = 70
#: Upper bound for the NAT gateway metrics to appear. Polls the VALUE, never asserts the latency.
_METRIC_DEADLINE_S = 600
#: NetworkPacketsOut is stored as 5-minute aggregates even under detailed monitoring (measured:
#: Period=60 over three minutes returned ONE datapoint while NetworkOut returned three), stamped at
#: the start of the 5-minute bucket. Its bucket can close up to five minutes after the transfer, so
#: it gets its own, longer deadline; the 600 s deadline still governs every NAT-gateway leg.
_PACKETS_DEADLINE_S = 900
_NAT_NS = "AWS/NATGateway"
_EC2_NS = "AWS/EC2"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway-cloudwatch.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """A guest's known byte transfer through NAT gateway A shows up in AWS/NATGateway byte and
    connection metrics on [NatGatewayId] and in the sender's AWS/EC2 NetworkOut/NetworkPacketsOut
    as at least the bytes sent, while an unrouted twin gateway B reports no bytes."""
    st: dict = {"subnets": [], "rt": [], "sgs": [], "instances": [], "eips": [], "nats": []}
    try:
        _build(ctx, st)
        _transfer_and_measure(ctx, st)
    finally:
        _teardown(ctx, st)


# ===== the fixture ==========================================================
def _build(ctx, st) -> None:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-obsnat-")
    st["name"] = name
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    zones = _usable_zones(ec2, 1)

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    _on_cleanup(ctx, lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(name)}],
    )["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw_id
    _on_cleanup(ctx, lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    public_a = _create_subnet(ctx, ec2, st, _PUBLIC_A_CIDR, zones[0], name + "-public-a")
    public_b = _create_subnet(ctx, ec2, st, _PUBLIC_B_CIDR, zones[0], name + "-public-b")
    private_subnet = _create_subnet(ctx, ec2, st, _PRIVATE_CIDR, zones[0], name + "-private")

    st["public_rt"] = _create_route_table(ctx, ec2, st, name + "-public-rt")
    _associate(ctx, ec2, st, st["public_rt"], public_a)
    _associate(ctx, ec2, st, st["public_rt"], public_b)
    ec2.create_route(RouteTableId=st["public_rt"], DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw_id)

    # Both gateways are created before either is waited on: the cost is the max, not the sum.
    for label, subnet in (("a", public_a), ("b", public_b)):
        alloc = ec2.allocate_address(
            Domain="vpc",
            TagSpecifications=[{"ResourceType": "elastic-ip",
                                "Tags": _tags_for(f"{name}-eip-{label}")}],
        )
        st["eips"].append(alloc["AllocationId"])
        _on_cleanup(ctx, lambda a=alloc["AllocationId"]: ec2.release_address(AllocationId=a))
        st[f"eip_{label}"] = alloc["PublicIp"]
        nat_id = ec2.create_nat_gateway(
            SubnetId=subnet, AllocationId=alloc["AllocationId"], ConnectivityType="public",
            TagSpecifications=[{"ResourceType": "natgateway",
                                "Tags": _tags_for(f"{name}-nat-{label}")}],
        )["NatGateway"]["NatGatewayId"]
        st["nats"].append(nat_id)
        st[f"nat_{label}"] = nat_id
        _on_cleanup(ctx, lambda n=nat_id: ec2.delete_nat_gateway(NatGatewayId=n))

    # The role and the sink can come up while the gateways provision.
    role_name = name + "-role"
    st["role"] = role_name
    st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    sink_sg = _create_sg(ctx, ec2, st, vpc_id, name + "-sink", "sim2real obs nat sink")
    sender_sg = _create_sg(ctx, ec2, st, vpc_id, name + "-sender", "sim2real obs nat sender")
    # The sink admits the transfer port from gateway A's address ONLY: a byte that reaches it can
    # only have left the VPC through gateway A.
    ec2.authorize_security_group_ingress(
        GroupId=sink_sg, IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": _SINK_PORT, "ToPort": _SINK_PORT,
            "IpRanges": [{"CidrIp": st["eip_a"] + "/32", "Description": "sim2real nat a only"}]}])
    st["sink"] = _launch(ctx, ec2, st, ami, sink_sg, public_a, name + "-sink",
                         public_ip=True, detailed=False)

    for label in ("a", "b"):
        nat_id = st[f"nat_{label}"]
        _poll(lambda n=nat_id: _nat_state(ec2, n), lambda s: s == "available",
              timeout_s=600, interval_s=10,
              what=f"NAT gateway {label} ({nat_id}) becoming available")
        described = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]
        addresses = [a.get("PublicIp") for a in described["NatGatewayAddresses"]]
        assert addresses == [st[f"eip_{label}"]], (
            f"NAT gateway {label} ({nat_id!r}) reports public addresses {addresses!r}; "
            f"AllocateAddress minted {st[f'eip_' + label]!r}"
        )
    assert st["eip_a"] != st["eip_b"], (
        f"both gateways hold the same Elastic IP {st['eip_a']!r}; the control rests on two")

    # Gateway A carries the private subnet. Gateway B is named only by a route table that no
    # subnet is associated with -- it is routable from nowhere.
    st["private_rt"] = _create_route_table(ctx, ec2, st, name + "-private-rt")
    _associate(ctx, ec2, st, st["private_rt"], private_subnet)
    ec2.create_route(RouteTableId=st["private_rt"], DestinationCidrBlock="0.0.0.0/0",
                     NatGatewayId=st["nat_a"])
    st["unused_rt"] = _create_route_table(ctx, ec2, st, name + "-unused-rt")
    ec2.create_route(RouteTableId=st["unused_rt"], DestinationCidrBlock="0.0.0.0/0",
                     NatGatewayId=st["nat_b"])
    unused = _route_table(ec2, st["unused_rt"])
    assert [a for a in unused.get("Associations", []) if a.get("SubnetId")] == [], (
        f"the control route table {st['unused_rt']!r} must have no subnet association; it has "
        f"{unused.get('Associations')!r}")

    st["sender"] = _launch(ctx, ec2, st, ami, sender_sg, private_subnet, name + "-sender",
                           public_ip=False, detailed=True)

    sink_desc = _describe_instance(ec2, st["sink"])
    st["sink_ip"] = sink_desc.get("PublicIpAddress")
    assert st["sink_ip"], f"the sink was launched with a public address but reports {sink_desc!r}"
    sender_desc = _poll(lambda: _describe_instance(ec2, st["sender"]),
                        lambda d: d.get("Monitoring", {}).get("State") == "enabled",
                        timeout_s=300, interval_s=10,
                        what=f"detailed monitoring on the sender {st['sender']} reading enabled")
    assert sender_desc.get("PublicIpAddress") is None, (
        f"the sender must have no public address, or its egress would bypass the NAT gateway: "
        f"{sender_desc.get('PublicIpAddress')!r}")

    for role, iid in (("sink", st["sink"]), ("sender", st["sender"])):
        info = _poll(lambda i=iid: _agent_view(ssm, i),
                     lambda v: v is not None and v.get("PingStatus") == "Online",
                     timeout_s=_SSM_ONLINE_TIMEOUT_S, interval_s=10,
                     what=f"the SSM agent on the {role} {iid} coming Online")
        assert info["PingStatus"] == "Online", f"{role} agent view was {info!r}"


# ===== the transfer and the telemetry =======================================
def _transfer_and_measure(ctx, st) -> None:
    ssm = ctx.client("ssm")
    cw = ctx.client("cloudwatch")

    # Barrier: a NAT gateway's telemetry begins minutes AFTER it reports `available`, and bytes it
    # carries before then are never published. Measured: a 32 MiB transfer ~2 min after
    # availability left NetworkOut at 35.2 MB for that minute while the gateway's first datapoint
    # of any kind was two minutes later -- the transfer's minute never appeared. So wait for the
    # gateway's own first datapoint (the SSM agent's traffic through it produces one) before
    # sending anything whose count is asserted.
    _poll(lambda: _recent_points(cw, st["nat_a"]), lambda n: n >= 1,
          timeout_s=_METRIC_DEADLINE_S, interval_s=20,
          what=f"NAT gateway {st['nat_a']} publishing its first BytesOutToDestination datapoint")

    # The sink listens first; the sender retries its connect, so ordering is not a race.
    sink_cmd = _send(ssm, st["sink"], _sink_script(accept_s=300))
    _poll(lambda: _invocation(ssm, sink_cmd, st["sink"]),
          lambda i: i is not None and i.get("Status") in ("InProgress",) + _TERMINAL,
          timeout_s=120, interval_s=3, what=f"the sink command {sink_cmd} starting")
    # LOWER BOUND of the send time: read BEFORE the sender's command exists.
    send_lb = datetime.datetime.now(datetime.timezone.utc)
    sender_cmd = _send(ssm, st["sender"], _sender_script(
        st["sink_ip"], connect_s=150))
    sender_inv = _wait_terminal(ssm, sender_cmd, st["sender"])
    sink_inv = _wait_terminal(ssm, sink_cmd, st["sink"])
    send_ub = datetime.datetime.now(datetime.timezone.utc)

    assert sender_inv["ResponseCode"] == 0, (
        f"the sender's transfer failed: status={sender_inv['Status']!r} "
        f"stdout={sender_inv['StandardOutputContent'][-400:]!r} "
        f"stderr={sender_inv['StandardErrorContent'][-400:]!r}")
    assert sink_inv["ResponseCode"] == 0, (
        f"the sink failed: status={sink_inv['Status']!r} "
        f"stdout={sink_inv['StandardOutputContent'][-400:]!r} "
        f"stderr={sink_inv['StandardErrorContent'][-400:]!r}")
    sent = _payload_json(sender_inv)
    sunk = _payload_json(sink_inv)
    assert sent.get("connected") is True and sent.get("sent") == _PAYLOAD_BYTES, (
        f"the sender reports {sent!r}, expected {_PAYLOAD_BYTES} bytes sent on one connection")
    assert sunk.get("accepted") is True and sunk.get("received") == _PAYLOAD_BYTES, (
        f"the sink reports {sunk!r}, expected exactly {_PAYLOAD_BYTES} bytes received")
    assert sunk["sha256"] == sent["sha256"], (
        f"the sink's digest {sunk['sha256']!r} differs from the sender's {sent['sha256']!r}")
    assert sunk.get("peer") == st["eip_a"], (
        f"the sink saw the connection come from {sunk.get('peer')!r}; the sender's only path out "
        f"is NAT gateway A, whose address is {st['eip_a']!r} (B holds {st['eip_b']!r})")
    assert (sent.get("ack") or {}).get("received") == _PAYLOAD_BYTES, (
        f"the sink's in-band acknowledgement read back by the sender was {sent.get('ack')!r}")

    start = _floor_minute(send_lb)
    end = _floor_minute(send_ub) + datetime.timedelta(minutes=2)
    floor_packets = -(-_PAYLOAD_BYTES // _MAX_FRAME_BYTES)
    p_start, p_end = _floor_5min(send_lb), _floor_5min(send_ub) + datetime.timedelta(minutes=5)
    poll_started = time.monotonic()
    nat_a, nat_b, sender = st["nat_a"], st["nat_b"], st["sender"]

    def _observe():
        o = {
            "nat_out": _stat(cw, _NAT_NS, "BytesOutToDestination", "NatGatewayId", nat_a,
                             start, end, "Sum"),
            "nat_in": _stat(cw, _NAT_NS, "BytesInFromSource", "NatGatewayId", nat_a,
                            start, end, "Sum"),
            "nat_active": _stat(cw, _NAT_NS, "ActiveConnectionCount", "NatGatewayId", nat_a,
                                start, end, "Maximum"),
            "nat_established": _stat(cw, _NAT_NS, "ConnectionEstablishedCount", "NatGatewayId",
                                     nat_a, start, end, "Sum"),
            "ec2_out": _stat(cw, _EC2_NS, "NetworkOut", "InstanceId", sender, start, end, "Sum"),
            "listed": _listed_dimension_sets(cw, nat_a),
        }
        return o

    def _done(o):
        return (o["nat_out"]["sum"] >= _PAYLOAD_BYTES and o["nat_in"]["sum"] >= _PAYLOAD_BYTES
                and o["nat_active"]["max"] >= 1 and o["nat_established"]["sum"] >= 1
                and o["ec2_out"]["sum"] >= _PAYLOAD_BYTES
                and [{"Name": "NatGatewayId", "Value": nat_a}] in o["listed"])

    seen = _poll(_observe, _done, timeout_s=_METRIC_DEADLINE_S, interval_s=20,
                 what=f"CloudWatch accounting for the {_PAYLOAD_BYTES}-byte transfer through "
                      f"{nat_a} over [{start.isoformat()}, {end.isoformat()})")
    remaining = max(0.0, _PACKETS_DEADLINE_S - (time.monotonic() - poll_started))
    seen["ec2_packets"] = _poll(
        lambda: _stat(cw, _EC2_NS, "NetworkPacketsOut", "InstanceId", sender, p_start, p_end,
                      "Sum", period=300),
        lambda o: o["sum"] >= floor_packets, timeout_s=remaining, interval_s=20,
        what=f"NetworkPacketsOut for {sender} reaching ceil({_PAYLOAD_BYTES}/{_MAX_FRAME_BYTES}) = "
             f"{floor_packets} over [{p_start.isoformat()}, {p_end.isoformat()}) at Period=300")

    for key, unit in (("nat_out", "Bytes"), ("nat_in", "Bytes"), ("nat_active", "Count"),
                      ("nat_established", "Count"), ("ec2_out", "Bytes"),
                      ("ec2_packets", "Count")):
        assert seen[key]["units"] == [unit], (
            f"{key} datapoints carry units {seen[key]['units']!r}, expected only {unit!r}")
    assert seen["nat_out"]["sum"] >= _PAYLOAD_BYTES, f"BytesOutToDestination {seen['nat_out']!r}"
    assert seen["nat_in"]["sum"] >= _PAYLOAD_BYTES, f"BytesInFromSource {seen['nat_in']!r}"
    assert seen["nat_active"]["max"] >= 1, f"ActiveConnectionCount {seen['nat_active']!r}"
    assert seen["nat_established"]["sum"] >= 1, (
        f"ConnectionEstablishedCount {seen['nat_established']!r}")
    assert seen["ec2_out"]["sum"] >= _PAYLOAD_BYTES, f"NetworkOut {seen['ec2_out']!r}"
    assert seen["ec2_packets"]["sum"] >= floor_packets, (
        f"NetworkPacketsOut {seen['ec2_packets']!r} is below ceil({_PAYLOAD_BYTES}/9001) = "
        f"{floor_packets}")
    assert all(s == [{"Name": "NatGatewayId", "Value": nat_a}] for s in seen["listed"]), (
        f"ListMetrics for {nat_a} returned dimension sets {seen['listed']!r}; every "
        f"AWS/NATGateway metric is published on exactly [NatGatewayId]")

    # Barrier passed: A's datapoints for these minutes are visible, so B's would be too.
    b_out = _stat(cw, _NAT_NS, "BytesOutToDestination", "NatGatewayId", nat_b, start, end, "Sum")
    b_in = _stat(cw, _NAT_NS, "BytesInFromSource", "NatGatewayId", nat_b, start, end, "Sum")
    print(f"[{CHECK[:24]}] window [{start.isoformat()}, {end.isoformat()}) a={seen!r} "
          f"b_out={b_out!r} b_in={b_in!r}")
    assert b_out["sum"] == 0, (
        f"control: NAT gateway B ({nat_b}) is reachable from no subnet yet reports "
        f"BytesOutToDestination {b_out!r} over the window in which A carried the transfer")
    assert b_in["sum"] == 0, (
        f"control: NAT gateway B ({nat_b}) reports BytesInFromSource {b_in!r}; no source in the "
        f"VPC routes to it")


def _stat(cw, namespace, metric, dim_name, dim_value, start, end, statistic, period=60) -> dict:
    """One GetMetricStatistics read (Period=60 unless stated) on EXACTLY one dimension, no Unit
    filter, so the unit the service stamps is observed rather than requested."""
    pts = _call_with_retry(lambda: cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric,
        Dimensions=[{"Name": dim_name, "Value": dim_value}],
        StartTime=start, EndTime=end, Period=period, Statistics=[statistic]))["Datapoints"]
    values = [p[statistic] for p in pts]
    return {"n": len(pts), "sum": sum(values), "max": max(values) if values else 0,
            "units": sorted({p.get("Unit") for p in pts})}


def _recent_points(cw, nat_id) -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    return _stat(cw, _NAT_NS, "BytesOutToDestination", "NatGatewayId", nat_id,
                 now - datetime.timedelta(minutes=20), now + datetime.timedelta(minutes=1),
                 "Sum")["n"]


def _listed_dimension_sets(cw, nat_id) -> list:
    out = []
    for page in cw.get_paginator("list_metrics").paginate(
            Namespace=_NAT_NS, MetricName="BytesOutToDestination",
            Dimensions=[{"Name": "NatGatewayId", "Value": nat_id}]):
        for m in page["Metrics"]:
            out.append(sorted(m["Dimensions"], key=lambda d: d["Name"]))
    return out


def _floor_minute(ts):
    return ts.replace(second=0, microsecond=0)


def _floor_5min(ts):
    return ts.replace(minute=ts.minute - ts.minute % 5, second=0, microsecond=0)


# ===== in-band teardown =====================================================
def _teardown(ctx, st) -> None:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises naming each one that failed on anything but an already-gone code."""
    found = sys.exc_info()[1]  # run from `finally:`; the in-flight error leads the message
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    def _vpc_gone():
        try:
            still = ec2.describe_vpcs(VpcIds=[st["vpc"]])["Vpcs"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidVpcID.NotFound":
                raise
            return
        raise RuntimeError(f"vpc {st['vpc']} is still describable: {still!r}")

    # Every delete is issued before any wait, so the cost is the max rather than the sum.
    if st.get("instances"):
        _step("instances", lambda: ec2.terminate_instances(InstanceIds=list(st["instances"])))
    for nat_id in st.get("nats", []):
        _step(f"nat {nat_id}", lambda n=nat_id: ec2.delete_nat_gateway(NatGatewayId=n))
    if st.get("instances"):
        _step("instances-terminated", lambda: _wait_terminated(ec2, st["instances"]))
    for nat_id in st.get("nats", []):
        _step(f"nat-deleted {nat_id}", lambda n=nat_id: _poll(
            lambda: _nat_state(ec2, n), lambda s: s in ("deleted", "gone"),
            timeout_s=600, interval_s=10, what=f"NAT gateway {n} reporting deleted"))
    for alloc in st.get("eips", []):
        _step(f"eip {alloc}", lambda a=alloc: _retry_dependency(
            lambda: ec2.release_address(AllocationId=a), codes=("InvalidIPAddress.InUse",)))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=600, interval_s=10, what=f"every ENI in {st['vpc']!r} draining"))
    for sg in reversed(st.get("sgs", [])):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for rt_id, assoc in st.get("rt", []):
        _step(f"rt-assoc {assoc}", lambda a=assoc: ec2.disassociate_route_table(AssociationId=a))
    for rt_id in st.get("rts", []):
        _step(f"rt {rt_id}", lambda r=rt_id: _retry_dependency(
            lambda: ec2.delete_route_table(RouteTableId=r)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    if st.get("igw"):
        _step("igw", lambda: _detach_and_delete_igw(ec2, st["igw"], st["vpc"]))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
        _step("vpc-gone", _vpc_gone)
    left: list = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 - collected, then raised below
            left.append(f"{label}: {exc!r}")
    if left:
        lead = f"{found!r}; " if found else ""
        raise AssertionError(f"{lead}teardown could not remove everything the check created: {left!r}")


# ===== helpers (self-contained) ==============================================
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidGroup.NotFound",
               "InvalidInternetGatewayID.NotFound", "InvalidInstanceID.NotFound",
               "InvalidAssociationID.NotFound", "InvalidAllocationID.NotFound",
               "NatGatewayNotFound", "InvalidNatGatewayID.NotFound")


def _on_cleanup(ctx, fn):
    """Register a failure-path delete that treats an already-gone resource as removed, since the
    in-band teardown normally deletes it first."""
    def _call():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise
    ctx.on_cleanup(_call)


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "obs-ec2-1-nat-metrics"},
            {"Key": "sim2real:managed", "Value": "true"}]


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=5.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _retry_dependency(fn, timeout_s=300, interval_s=10, codes=("DependencyViolation",)):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _usable_zones(ec2, want):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= want, (
        f"this check needs {want} available AZs offering {_INSTANCE_TYPE}; the intersection of "
        f"offerings {sorted(offered)!r} with the available zones is {usable!r}")
    return usable[:want]


def _create_subnet(ctx, ec2, st, cidr, zone, tag_name):
    subnet_id = ec2.create_subnet(
        VpcId=st["vpc"], CidrBlock=cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    _on_cleanup(ctx, lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


def _associate(ctx, ec2, st, rt_id, subnet_id):
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    st["rt"].append((rt_id, assoc))
    _on_cleanup(ctx, lambda: ec2.disassociate_route_table(AssociationId=assoc))
    return assoc


def _create_route_table(ctx, ec2, st, tag_name):
    rt_id = ec2.create_route_table(
        VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(tag_name)}],
    )["RouteTable"]["RouteTableId"]
    st.setdefault("rts", []).append(rt_id)
    _on_cleanup(ctx, lambda: ec2.delete_route_table(RouteTableId=rt_id))
    return rt_id


def _create_sg(ctx, ec2, st, vpc_id, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    _on_cleanup(ctx, lambda: ec2.delete_security_group(GroupId=sg))
    return sg


def _nat_state(ec2, nat_id):
    try:
        nats = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in (
                "NatGatewayNotFound", "InvalidNatGatewayID.NotFound"):
            return "gone"
        raise
    return nats[0]["State"] if nats else "gone"


def _route_table(ec2, rt_id):
    return ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]


def _vpc_enis(ec2, vpc_id):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]]


def _launch(ctx, ec2, st, ami, sg, subnet_id, tag_name, public_ip, detailed):
    instance_id = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg],
                                "AssociatePublicIpAddress": public_ip}],
            IamInstanceProfile={"Name": st["profile"]},
            Monitoring={"Enabled": detailed},
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                               for rt in ("instance", "volume", "network-interface")],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )["Instances"][0]["InstanceId"]
    # Registered IMMEDIATELY: an instance that never boots still bills.
    st["instances"].append(instance_id)
    _on_cleanup(ctx, lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return instance_id


def _describe_instance(ec2, instance_id):
    return _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=[instance_id]),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=12, delay=5.0,
    )["Reservations"][0]["Instances"][0]


def _wait_terminated(ec2, instance_ids, timeout_s=600):
    _poll(lambda: [i["State"]["Name"]
                   for r in _call_with_retry(
                       lambda: ec2.describe_instances(InstanceIds=list(instance_ids)),
                       codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                       retries=12, delay=5.0)["Reservations"]
                   for i in r["Instances"]],
          lambda states: all(s == "terminated" for s in states),
          timeout_s=timeout_s, interval_s=10,
          what=f"instances {list(instance_ids)!r} reaching terminated")


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real obs nat metrics host",
                    Tags=[{"Key": "sim2real", "Value": "obs-ec2-1-nat-metrics"}])
    _on_cleanup(ctx, lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    _on_cleanup(ctx, lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=_SSM_CORE_POLICY))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "obs-ec2-1-nat-metrics"}])
    _on_cleanup(ctx, lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    _on_cleanup(ctx, lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name))
    # IAM exposes no "this profile is usable" condition to poll; RunInstances' own bounded retry on
    # InvalidParameterValue in _launch is what makes first use correct.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(10):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 9:
                raise
            time.sleep(5)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    for attempt in range(10):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DeleteConflict" and attempt < 9:
                time.sleep(5)
                continue
            raise


def _detach_and_delete_igw(ec2, igw_id, vpc_id):
    try:
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "Gateway.NotAttached":
            raise
    _retry_dependency(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _send(ssm, instance_id, script):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script], "executionTimeout": [str(_PHASE_TIMEOUT_S)]},
        TimeoutSeconds=600, Comment="sim2real obs-ec2-1 nat metrics"))
    return sent["Command"]["CommandId"]


def _invocation(ssm, command_id, instance_id):
    try:
        return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
            return None
        raise


def _wait_terminal(ssm, command_id, instance_id):
    return _poll(lambda: _invocation(ssm, command_id, instance_id),
                 lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=_PHASE_TIMEOUT_S + 60, interval_s=5.0,
                 what=f"invocation {command_id} on {instance_id} reaching a terminal status")


def _payload_json(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout at all: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


def _sink_script(accept_s) -> str:
    """Accept ONE connection on the transfer port, count and digest every byte until EOF, send the
    count back in-band, and print what was received and from which address."""
    return f"""python3 - <<'PYEOF'
import hashlib, json, socket, sys
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", {_SINK_PORT}))
srv.listen(4)
srv.settimeout({accept_s})
try:
    conn, peer = srv.accept()
except socket.timeout:
    print(json.dumps({{"accepted": False}}))
    sys.exit(0)
conn.settimeout(240)
digest = hashlib.sha256()
total = 0
while True:
    data = conn.recv(65536)
    if not data:
        break
    total += len(data)
    digest.update(data)
ack = {{"received": total, "sha256": digest.hexdigest()}}
conn.sendall(json.dumps(ack).encode())
conn.close()
print(json.dumps(dict(ack, accepted=True, peer=peer[0])))
PYEOF"""


def _sender_script(host, connect_s) -> str:
    """Connect to the sink (retrying while it starts listening), send exactly _PAYLOAD_BYTES on one
    connection, hold it open across a metric sample, half-close, and read the sink's ack."""
    return f"""python3 - <<'PYEOF'
import hashlib, json, socket, sys, time
deadline = time.time() + {connect_s}
while True:
    try:
        sock = socket.create_connection(("{host}", {_SINK_PORT}), timeout=10)
        break
    except OSError as exc:
        if time.time() > deadline:
            print(json.dumps({{"connected": False, "error": repr(exc)}}))
            sys.exit(3)
        time.sleep(3)
chunk = bytes(range(256)) * 256
digest = hashlib.sha256()
sent = 0
while sent < {_PAYLOAD_BYTES}:
    block = chunk[:min(len(chunk), {_PAYLOAD_BYTES} - sent)]
    sock.sendall(block)
    digest.update(block)
    sent += len(block)
time.sleep({_HOLD_OPEN_S})
sock.shutdown(socket.SHUT_WR)
sock.settimeout(120)
raw = b""
while True:
    data = sock.recv(65536)
    if not data:
        break
    raw += data
sock.close()
print(json.dumps({{"connected": True, "sent": sent, "sha256": digest.hexdigest(),
                  "ack": json.loads(raw.decode() or "null")}}))
PYEOF"""


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
