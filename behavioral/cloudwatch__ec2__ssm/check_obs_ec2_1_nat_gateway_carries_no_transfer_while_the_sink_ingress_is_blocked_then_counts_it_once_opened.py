"""obs-ec2-1-nat-gateway-carries-no-transfer-while-the-sink-ingress-is-blocked-then-counts-it-once-opened."""
from __future__ import annotations

import datetime
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-ec2-1-nat-gateway-carries-no-transfer-while-the-sink-ingress-is-blocked-then-counts-it-once-opened"
GROUP = "nat-gateway-metrics"
SERVICES = ["cloudwatch", "ec2", "ssm"]

_VPC_CIDR = "10.74.0.0/16"
_PUBLIC_CIDR = "10.74.0.0/24"
_PRIVATE_CIDR = "10.74.10.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_SSM_ONLINE_TIMEOUT_S = 600
_PHASE_TIMEOUT_S = 420
#: The known byte count. 32 MiB is far above what the SSM agent's own traffic and a few dropped
#: SYNs move through the gateway in a minute, so "fewer than N bytes" is a property of the block,
#: not of a quiet gateway.
_PAYLOAD_BYTES = 32 * 1024 * 1024
_SINK_PORT = 5201
_HOLD_OPEN_S = 5
#: How long the blocked sender keeps trying. Several 10 s connect attempts, so a slow-to-apply
#: rule cannot be mistaken for a block.
_BLOCKED_CONNECT_S = 40
_METRIC_DEADLINE_S = 600
_NAT_NS = "AWS/NATGateway"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway-cloudwatch.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """With no sink ingress, a guest's TCP connect through a NAT gateway times out and the gateway's
    Period=60 byte metrics stay below the payload; admitting the gateway's EIP delivers the payload
    byte-exact and both NAT byte metrics count it.
    """
    st: dict = {"subnets": [], "rt": [], "sgs": [], "instances": [], "eips": [], "nats": []}
    # Teardown is in-band: ctx cleanups are too short-lived to wait out instance termination and a
    # NAT gateway delete.
    try:
        _build(ctx, st)
        _blocked_then_opened(ctx, st)
    finally:
        _teardown(ctx, st)


# ===== the fixture ==========================================================
def _build(ctx, st) -> None:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-obsnatblk-")
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

    public = _create_subnet(ctx, ec2, st, _PUBLIC_CIDR, zones[0], name + "-public")
    private_subnet = _create_subnet(ctx, ec2, st, _PRIVATE_CIDR, zones[0], name + "-private")
    st["public_rt"] = _create_route_table(ctx, ec2, st, name + "-public-rt")
    _associate(ctx, ec2, st, st["public_rt"], public)
    ec2.create_route(RouteTableId=st["public_rt"], DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw_id)

    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": _tags_for(name + "-eip")}],
    )
    st["eips"].append(alloc["AllocationId"])
    _on_cleanup(ctx, lambda: ec2.release_address(AllocationId=alloc["AllocationId"]))
    st["eip"] = alloc["PublicIp"]
    nat_id = ec2.create_nat_gateway(
        SubnetId=public, AllocationId=alloc["AllocationId"], ConnectivityType="public",
        TagSpecifications=[{"ResourceType": "natgateway", "Tags": _tags_for(name + "-nat")}],
    )["NatGateway"]["NatGatewayId"]
    st["nats"].append(nat_id)
    st["nat"] = nat_id
    _on_cleanup(ctx, lambda: ec2.delete_nat_gateway(NatGatewayId=nat_id))

    role_name = name + "-role"
    st["role"] = role_name
    st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    # The sink's group starts with NO ingress at all: the one thing this check breaks.
    st["sink_sg"] = _create_sg(ctx, ec2, st, vpc_id, name + "-sink", "sim2real obs nat sink")
    sender_sg = _create_sg(ctx, ec2, st, vpc_id, name + "-sender", "sim2real obs nat sender")
    st["sink"] = _launch(ctx, ec2, st, ami, st["sink_sg"], public, name + "-sink",
                         public_ip=True, detailed=False)

    _poll(lambda: _nat_state(ec2, nat_id), lambda s: s == "available",
          timeout_s=600, interval_s=10, what=f"NAT gateway {nat_id} becoming available")
    described = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]
    addresses = [a.get("PublicIp") for a in described["NatGatewayAddresses"]]
    assert addresses == [st["eip"]], (
        f"NAT gateway {nat_id!r} reports public addresses {addresses!r}; AllocateAddress minted "
        f"{st['eip']!r}")

    st["private_rt"] = _create_route_table(ctx, ec2, st, name + "-private-rt")
    _associate(ctx, ec2, st, st["private_rt"], private_subnet)
    ec2.create_route(RouteTableId=st["private_rt"], DestinationCidrBlock="0.0.0.0/0",
                     NatGatewayId=nat_id)
    st["sender"] = _launch(ctx, ec2, st, ami, sender_sg, private_subnet, name + "-sender",
                           public_ip=False, detailed=False)

    sink_desc = _describe_instance(ec2, st["sink"])
    st["sink_ip"] = sink_desc.get("PublicIpAddress")
    assert st["sink_ip"], f"the sink was launched with a public address but reports {sink_desc!r}"
    sender_desc = _describe_instance(ec2, st["sender"])
    assert sender_desc.get("PublicIpAddress") is None, (
        f"the sender must have no public address, or its egress would bypass the NAT gateway: "
        f"{sender_desc.get('PublicIpAddress')!r}")
    ingress = ec2.describe_security_groups(GroupIds=[st["sink_sg"]])["SecurityGroups"][0]
    assert ingress["IpPermissions"] == [], (
        f"the sink's group must start with no ingress, it holds {ingress['IpPermissions']!r}")

    for role, iid in (("sink", st["sink"]), ("sender", st["sender"])):
        info = _poll(lambda i=iid: _agent_view(ssm, i),
                     lambda v: v is not None and v.get("PingStatus") == "Online",
                     timeout_s=_SSM_ONLINE_TIMEOUT_S, interval_s=10,
                     what=f"the SSM agent on the {role} {iid} coming Online")
        assert info["PingStatus"] == "Online", f"{role} agent view was {info!r}"


# ===== the two phases =======================================================
def _phase(ctx, ssm, st, accept_s, connect_s):
    """One transfer attempt: sink listening first, sender after, both read to a terminal status.
    Returns (lower bound, upper bound, sender report, sink report)."""
    sink_cmd = _send(ssm, st["sink"], _sink_script(accept_s=accept_s))
    _poll(lambda: _invocation(ssm, sink_cmd, st["sink"]),
          lambda i: i is not None and i.get("Status") in ("InProgress",) + _TERMINAL,
          timeout_s=120, interval_s=3, what=f"the sink command {sink_cmd} starting")
    lb = datetime.datetime.now(datetime.timezone.utc)
    sender_cmd = _send(ssm, st["sender"], _sender_script(
        st["sink_ip"], connect_s=connect_s))
    sender_inv = _wait_terminal(ssm, sender_cmd, st["sender"])
    sink_inv = _wait_terminal(ssm, sink_cmd, st["sink"])
    ub = datetime.datetime.now(datetime.timezone.utc)
    assert sink_inv["ResponseCode"] == 0, (
        f"the sink failed: status={sink_inv['Status']!r} "
        f"stdout={sink_inv['StandardOutputContent'][-400:]!r} "
        f"stderr={sink_inv['StandardErrorContent'][-400:]!r}")
    return lb, ub, sender_inv, _payload_json(sink_inv)


def _blocked_then_opened(ctx, st) -> None:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    cw = ctx.client("cloudwatch")
    nat = st["nat"]

    # Barrier: a NAT gateway's telemetry begins minutes after it reports `available`, and earlier
    # minutes are never published. The blocked window must hold published datapoints, so wait for
    # the first one (the SSM agent's own traffic produces it) before phase 1 starts.
    _poll(lambda: _recent_points(cw, nat), lambda n: n >= 1,
          timeout_s=_METRIC_DEADLINE_S, interval_s=20,
          what=f"NAT gateway {nat} publishing its first BytesOutToDestination datapoint")

    # --- phase 1: the sink admits nothing ---------------------------------------------------
    lb1, ub1, sender1, sink1 = _phase(ctx, ssm, st, accept_s=_BLOCKED_CONNECT_S + 30,
                                      connect_s=_BLOCKED_CONNECT_S)
    blocked = _payload_json(sender1)
    assert sender1["ResponseCode"] == 3 and blocked.get("connected") is False, (
        f"with no ingress rule on the sink the sender must fail to connect (rc 3); it reported "
        f"rc={sender1['ResponseCode']!r} {blocked!r}")
    assert blocked.get("error_kind") == "timeout", (
        f"a security group DROPS, so the connect must time out rather than be refused or reset; "
        f"the guest saw {blocked!r}")
    assert sink1 == {"accepted": False}, (
        f"effect absent: the sink must have accepted no connection while blocked, it reports "
        f"{sink1!r}")

    # Separate the windows by a minute boundary, so no Period=60 bucket holds both phases.
    boundary = _floor_minute(ub1) + datetime.timedelta(minutes=1)
    _poll(lambda: datetime.datetime.now(datetime.timezone.utc), lambda now: now >= boundary,
          timeout_s=75, interval_s=2, what=f"the clock passing the minute boundary {boundary}")

    # --- phase 2: change exactly ONE thing -- admit the gateway's address ---------------------
    ec2.authorize_security_group_ingress(
        GroupId=st["sink_sg"], IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": _SINK_PORT, "ToPort": _SINK_PORT,
            "IpRanges": [{"CidrIp": st["eip"] + "/32", "Description": "sim2real nat only"}]}])
    lb2, ub2, sender2, sink2 = _phase(ctx, ssm, st, accept_s=300, connect_s=150)
    assert sender2["ResponseCode"] == 0, (
        f"control: with the gateway's address admitted the transfer must succeed; "
        f"rc={sender2['ResponseCode']!r} stdout={sender2['StandardOutputContent'][-400:]!r}")
    sent = _payload_json(sender2)
    assert sent.get("connected") is True and sent.get("sent") == _PAYLOAD_BYTES, (
        f"control: the sender reports {sent!r}, expected {_PAYLOAD_BYTES} bytes sent")
    assert sink2.get("accepted") is True and sink2.get("received") == _PAYLOAD_BYTES, (
        f"control: the sink reports {sink2!r}, expected exactly {_PAYLOAD_BYTES} bytes")
    assert sink2["sha256"] == sent["sha256"] and sink2.get("peer") == st["eip"], (
        f"control: the sink received digest {sink2['sha256']!r} from {sink2.get('peer')!r}; the "
        f"sender sent {sent['sha256']!r} and its only path out is the gateway at {st['eip']!r}")

    w1 = (_floor_minute(lb1), boundary)
    w2 = (boundary, _floor_minute(ub2) + datetime.timedelta(minutes=2))
    assert lb2 >= boundary, f"phase 2 began at {lb2} before the window boundary {boundary}"

    def _observe():
        return {"out": _stat(cw, _NAT_NS, "BytesOutToDestination", "NatGatewayId", nat, *w2,
                             "Sum"),
                "in": _stat(cw, _NAT_NS, "BytesInFromSource", "NatGatewayId", nat, *w2, "Sum")}

    opened = _poll(_observe,
                   lambda o: o["out"]["sum"] >= _PAYLOAD_BYTES and o["in"]["sum"] >= _PAYLOAD_BYTES,
                   timeout_s=_METRIC_DEADLINE_S, interval_s=20,
                   what=f"AWS/NATGateway counting the opened transfer through {nat} over "
                        f"[{w2[0].isoformat()}, {w2[1].isoformat()})")
    for key in ("out", "in"):
        assert opened[key]["units"] == ["Bytes"], (
            f"control: {key} datapoints carry units {opened[key]['units']!r}, expected Bytes")

    # Later minutes on this gateway are visible, so the blocked window's datapoints are too; it
    # must also hold datapoints, so "fewer than N" is not "not published yet".
    out1 = _stat(cw, _NAT_NS, "BytesOutToDestination", "NatGatewayId", nat, *w1, "Sum")
    in1 = _stat(cw, _NAT_NS, "BytesInFromSource", "NatGatewayId", nat, *w1, "Sum")
    print(f"[{CHECK[:24]}] blocked {w1[0].isoformat()}..{w1[1].isoformat()} out={out1!r} "
          f"in={in1!r} | opened {w2[0].isoformat()}..{w2[1].isoformat()} {opened!r}")
    assert out1["n"] >= 1 and in1["n"] >= 1, (
        f"the blocked window must hold published datapoints for {nat}, or 'fewer bytes' is only "
        f"'not published yet': BytesOutToDestination {out1!r}, BytesInFromSource {in1!r}")
    assert out1["sum"] < _PAYLOAD_BYTES, (
        f"effect absent: while the sink admitted nothing, {nat} reports BytesOutToDestination "
        f"{out1!r}, at least the {_PAYLOAD_BYTES} bytes that never left the guest")
    assert in1["sum"] < _PAYLOAD_BYTES, (
        f"effect absent: while blocked, {nat} reports BytesInFromSource {in1!r}, at least the "
        f"{_PAYLOAD_BYTES} bytes the guest never managed to send")


def _stat(cw, namespace, metric, dim_name, dim_value, start, end, statistic) -> dict:
    """One GetMetricStatistics read at Period=60 on EXACTLY one dimension, no Unit filter, so the
    unit the service stamps is observed rather than requested."""
    pts = _call_with_retry(lambda: cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric,
        Dimensions=[{"Name": dim_name, "Value": dim_value}],
        StartTime=start, EndTime=end, Period=60, Statistics=[statistic]))["Datapoints"]
    values = [p[statistic] for p in pts]
    return {"n": len(pts), "sum": sum(values), "max": max(values) if values else 0,
            "units": sorted({p.get("Unit") for p in pts})}


def _recent_points(cw, nat_id) -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    return _stat(cw, _NAT_NS, "BytesOutToDestination", "NatGatewayId", nat_id,
                 now - datetime.timedelta(minutes=20), now + datetime.timedelta(minutes=1),
                 "Sum")["n"]


def _floor_minute(ts):
    return ts.replace(second=0, microsecond=0)


# ===== in-band teardown =====================================================
def _teardown(ctx, st) -> None:
    """Ordered teardown with the waits ctx cleanups cannot afford. Runs every step, then raises
    naming each one that failed on anything but an already-gone code."""
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
            {"Key": "sim2real", "Value": "obs-ec2-1-nat-blocked"},
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
                    Tags=[{"Key": "sim2real", "Value": "obs-ec2-1-nat-blocked"}])
    _on_cleanup(ctx, lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    _on_cleanup(ctx, lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=_SSM_CORE_POLICY))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "obs-ec2-1-nat-blocked"}])
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
            kind = ("timeout" if isinstance(exc, socket.timeout)
                    else "refused" if isinstance(exc, ConnectionRefusedError) else "other")
            print(json.dumps({{"connected": False, "error_kind": kind, "error": repr(exc)}}))
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
