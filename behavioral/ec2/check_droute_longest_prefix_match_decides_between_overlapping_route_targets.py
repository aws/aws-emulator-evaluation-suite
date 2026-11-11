"""droute-longest-prefix-match-decides-between-overlapping-route-targets."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "droute-longest-prefix-match-decides-between-overlapping-route-targets"
GROUP = "route-table-data-plane"
SERVICES = ["ec2"]

_CLIENT_VPC_CIDR = "10.140.0.0/16"
_CLIENT_SUBNET_CIDR = "10.140.1.0/24"
_PEER_VPC_CIDR = "10.141.0.0/16"
_S1_SUBNET_CIDR = "10.141.1.0/24"
_S2_SUBNET_CIDR = "10.141.2.0/24"
_S1_IP = "10.141.1.10"
_S2_IP = "10.141.2.10"
_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
#: curl(1) exit statuses. 28 is "Operation timeout" -- a packet that was silently DROPPED. 7 is
#: "Failed to connect", which is what a REFUSED connection (an RST) looks like. A route to a target
#: that will not deliver produces 28; anything else means the packet was answered.
_CURL_TIMEOUT = 28


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """When an active /16 and /24 cover a destination with different targets, the /24 decides where
    the packet goes, both when it drops and when it delivers, as observed by curl from a guest.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "instances": [], "rts": [], "rt_assocs": [],
                "igws": [], "vpcs": [], "pcx": None, "role": None, "profile": None}
    # Teardown runs in-band, in order: instances terminate before the gateways detach and the
    # subnets delete.
    try:
        _build(ctx, ec2, ssm, iam, st)
        _legs(ec2, ssm, st)
    except BaseException as exc:
        _teardown(ec2, iam, st, cause=exc)
        raise
    _teardown(ec2, iam, st)


# ===== the estate ===========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-droute-lpm-")
    st["name"] = name
    st["nonce_s1"] = name + "-s1"
    st["nonce_s2"] = name + "-s2"

    # Every decidable precondition ahead of the first create: an AZ that cannot run the instance
    # type is an answer available now, and finding it out after three launches bills for nothing.
    zone = _usable_zone(ec2)

    vpc_a = _create_vpc(ctx, ec2, st, _CLIENT_VPC_CIDR, name + "-client-vpc")
    vpc_b = _create_vpc(ctx, ec2, st, _PEER_VPC_CIDR, name + "-peer-vpc")
    st["vpc_a"], st["vpc_b"] = vpc_a, vpc_b

    igw_a = _create_igw(ctx, ec2, st, vpc_a, name + "-client-igw")
    igw_b = _create_igw(ctx, ec2, st, vpc_b, name + "-peer-igw")
    st["igw_a"] = igw_a

    client_subnet = _create_subnet(ctx, ec2, st, vpc_a, _CLIENT_SUBNET_CIDR, zone,
                                   name + "-client-subnet")
    s1_subnet = _create_subnet(ctx, ec2, st, vpc_b, _S1_SUBNET_CIDR, zone, name + "-s1-subnet")
    s2_subnet = _create_subnet(ctx, ec2, st, vpc_b, _S2_SUBNET_CIDR, zone, name + "-s2-subnet")

    # The route table under test: a CUSTOM one associated with the client subnet, so no leg ever
    # mutates the VPC's main table and nothing outside this check can be affected by a leg.
    rt_a = _create_rt(ctx, ec2, st, vpc_a, name + "-client-rt")
    st["rt_a"] = rt_a
    ec2.create_route(RouteTableId=rt_a, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_a)
    _associate_rt(ctx, ec2, st, rt_a, client_subnet)

    rt_b = _create_rt(ctx, ec2, st, vpc_b, name + "-peer-rt")
    st["rt_b"] = rt_b
    ec2.create_route(RouteTableId=rt_b, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_b)
    _associate_rt(ctx, ec2, st, rt_b, s1_subnet)
    _associate_rt(ctx, ec2, st, rt_b, s2_subnet)

    sg_client = _create_sg(ctx, ec2, st, vpc_a, name + "-client-sg", "sim2real droute lpm client")
    sg_server = _create_sg(ctx, ec2, st, vpc_b, name + "-server-sg", "sim2real droute lpm server")
    ec2.authorize_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": _CLIENT_VPC_CIDR}]}])

    # The peering connection, accepted and active before any route names it.
    pcx = ec2.create_vpc_peering_connection(
        VpcId=vpc_a, PeerVpcId=vpc_b,
        TagSpecifications=[{"ResourceType": "vpc-peering-connection",
                            "Tags": _tags_for(name + "-pcx")}],
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    st["pcx"] = pcx
    ctx.on_cleanup(_net(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)))
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "pending-acceptance",
          timeout_s=180, interval_s=3,
          what=f"peering connection {pcx} reaching pending-acceptance")
    _call_with_retry(lambda: ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx))
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "active", timeout_s=180, interval_s=5,
          what=f"peering connection {pcx} becoming active")

    # The return path lives in the PEER vpc's table and is never touched by a leg, so every leg's
    # outcome is a property of the client-side table alone.
    ec2.create_route(RouteTableId=rt_b, DestinationCidrBlock=_CLIENT_VPC_CIDR,
                     VpcPeeringConnectionId=pcx)

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    st["s1"] = _launch(ctx, ec2, st, ami, s1_subnet, sg_server, name + "-s1",
                       user_data=_server_user_data(st["nonce_s1"]), private_ip=_S1_IP)
    st["s2"] = _launch(ctx, ec2, st, ami, s2_subnet, sg_server, name + "-s2",
                       user_data=_server_user_data(st["nonce_s2"]), private_ip=_S2_IP)
    st["client"] = _launch(ctx, ec2, st, ami, client_subnet, sg_client, name + "-client")

    for label, iid in (("s1", st["s1"]), ("s2", st["s2"]), ("client", st["client"])):
        info = _poll(lambda iid=iid: _agent_view(ssm, iid),
                     lambda i: i is not None and i.get("PingStatus") == "Online",
                     timeout_s=600, interval_s=10,
                     what=f"the SSM agent on the {label} {iid} coming Online")
        assert info["PingStatus"] == "Online", f"the {label}'s agent view was {info!r}"

    # RunInstances is eventually consistent: DescribeInstances can 404 an id it just minted.
    described = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=[st["s1"], st["s2"], st["client"]]),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=12, delay=5.0)["Reservations"]
    by_id = {i["InstanceId"]: i for r in described for i in r["Instances"]}
    assert by_id[st["s1"]]["PrivateIpAddress"] == _S1_IP, (
        f"s1 did not take the address inside the /24 under test: "
        f"{by_id[st['s1']]['PrivateIpAddress']!r}, expected {_S1_IP!r}")
    assert by_id[st["s2"]]["PrivateIpAddress"] == _S2_IP, (
        f"s2 did not take the address OUTSIDE the /24 under test: "
        f"{by_id[st['s2']]['PrivateIpAddress']!r}, expected {_S2_IP!r}")
    st["client_ip"] = by_id[st["client"]]["PrivateIpAddress"]

    # The barrier: nothing below is interpretable unless both servers actually serve.
    for label, iid, nonce in (("s1", st["s1"], st["nonce_s1"]), ("s2", st["s2"], st["nonce_s2"])):
        view = _poll(lambda iid=iid: _server_view(ssm, iid, st["client_ip"]),
                     lambda v: v["local"] == nonce, timeout_s=300, interval_s=10,
                     what=f"{label} answering its own listener on 127.0.0.1 with {nonce!r}")
        assert view["local"] == nonce, (
            f"{label} must serve its own nonce before any leg runs; it returned {view!r}")


# ===== the four legs ========================================================
def _legs(ec2, ssm, st) -> None:
    rt_a, pcx, igw_a = st["rt_a"], st["pcx"], st["igw_a"]

    # --- L1: only the /16, pointing at the peering connection -----------------
    ec2.create_route(RouteTableId=rt_a, DestinationCidrBlock=_PEER_VPC_CIDR,
                     VpcPeeringConnectionId=pcx)
    supernet = _route(ec2, rt_a, _PEER_VPC_CIDR)
    assert supernet["State"] == "active", (
        f"the /16 must be ACTIVE for L1 to mean anything: {supernet!r}")
    assert supernet.get("VpcPeeringConnectionId") == pcx, (
        f"the /16 must target the peering connection {pcx!r}: {supernet!r}")
    assert _route_or_none(ec2, rt_a, _S1_SUBNET_CIDR) is None, (
        f"no /24 may exist in L1, or the baseline is not a baseline: "
        f"{_routes(ec2, rt_a)!r}")

    l1 = _probe(ssm, st, s1_ok=True, s2_ok=True, what="L1 baseline with only the /16 -> peering")
    assert l1["s1"]["body"] == st["nonce_s1"], (
        f"L1 must reach s1 through the /16 and get s1's own nonce: {l1['s1']!r}")
    assert l1["s2"]["body"] == st["nonce_s2"], (
        f"L1 must reach s2 through the /16 and get s2's own nonce: {l1['s2']!r}")
    base_s1 = _server_view(ssm, st["s1"], st["client_ip"])
    base_s2 = _server_view(ssm, st["s2"], st["client_ip"])
    assert int(base_s1["hits"]) > 0 and int(base_s2["hits"]) > 0, (
        f"both servers must have logged L1's request from {st['client_ip']!r}: "
        f"s1={base_s1!r} s2={base_s2!r}")

    # --- L2: a more specific /24 pointing at a target that cannot deliver -----
    ec2.create_route(RouteTableId=rt_a, DestinationCidrBlock=_S1_SUBNET_CIDR, GatewayId=igw_a)
    specific = _route(ec2, rt_a, _S1_SUBNET_CIDR)
    assert specific["State"] == "active", (
        f"the /24 must be ACTIVE, not blackhole -- otherwise L2 is a blackhole test and says "
        f"nothing about specificity: {specific!r}")
    assert specific.get("GatewayId") == igw_a, (
        f"the /24 must target the internet gateway {igw_a!r}: {specific!r}")
    still = _route(ec2, rt_a, _PEER_VPC_CIDR)
    assert still["State"] == "active" and still.get("VpcPeeringConnectionId") == pcx, (
        f"the /16 must still be active and still point at the peering connection, or the /24 is "
        f"not competing with anything: {still!r}")

    l2, l2_s1_base, l2_s1_after = _blocked_leg(
        ssm, st, "s1", s1_ok=False, s2_ok=True,
        what="L2 with 10.141.1.0/24 -> internet gateway over 10.141.0.0/16 -> peering")
    assert l2["s1"]["body"] == "", (
        f"L2 must get no body from s1: something answered a packet that should have been dropped "
        f"at the internet gateway: {l2['s1']!r}")
    assert l2["s2"]["body"] == st["nonce_s2"], (
        f"s2 is covered only by the /16 -> peering and must STILL be reachable in L2; without this "
        f"positive control the leg cannot tell a specific-route win from a broken peering: "
        f"{l2['s2']!r}")
    assert int(l2_s1_after["hits"]) == int(l2_s1_base["hits"]), (
        f"the /24 sent the packet to the internet gateway, which drops a private destination, so "
        f"s1's own access log must not grow across one further attempt: "
        f"{l2_s1_base['hits']!r} -> {l2_s1_after['hits']!r}")
    assert l2_s1_after["local"] == st["nonce_s1"], (
        f"s1 must still answer its own listener, or L2 is evidence about a dead host rather than "
        f"about the route: {l2_s1_after!r}")
    after_l2_s2 = _server_view(ssm, st["s2"], st["client_ip"])
    assert int(after_l2_s2["hits"]) > int(base_s2["hits"]), (
        f"s2's access log must record L2's request, proving the peering connection carried traffic "
        f"throughout the leg: {base_s2['hits']!r} -> {after_l2_s2['hits']!r}")

    # --- L3: delete the /24, the /16 takes over again -------------------------
    ec2.delete_route(RouteTableId=rt_a, DestinationCidrBlock=_S1_SUBNET_CIDR)
    assert _route_or_none(ec2, rt_a, _S1_SUBNET_CIDR) is None, (
        f"the /24 must be gone: {_routes(ec2, rt_a)!r}")
    l3 = _probe(ssm, st, s1_ok=True, s2_ok=True, what="L3 after the /24 was deleted")
    assert l3["s1"]["body"] == st["nonce_s1"], (
        f"deleting the /24 must restore s1 through the /16: {l3['s1']!r}")
    l3_s1 = _server_view(ssm, st["s1"], st["client_ip"])
    assert int(l3_s1["hits"]) > int(l2_s1_after["hits"]), (
        f"L3's request must reach s1 and be logged, closing the bracket around L2's absence: "
        f"{l2_s1_after['hits']!r} -> {l3_s1['hits']!r}")

    # --- L4: the SAME two targets, assigned the OTHER way round --------------
    ec2.replace_route(RouteTableId=rt_a, DestinationCidrBlock=_PEER_VPC_CIDR, GatewayId=igw_a)
    ec2.create_route(RouteTableId=rt_a, DestinationCidrBlock=_S2_SUBNET_CIDR,
                     VpcPeeringConnectionId=pcx)
    flipped = _route(ec2, rt_a, _PEER_VPC_CIDR)
    assert flipped["State"] == "active" and flipped.get("GatewayId") == igw_a, (
        f"the /16 must now be an ACTIVE route to the internet gateway: {flipped!r}")
    assert "VpcPeeringConnectionId" not in flipped, (
        f"the /16 must no longer name the peering connection at all: {flipped!r}")
    narrow = _route(ec2, rt_a, _S2_SUBNET_CIDR)
    assert narrow["State"] == "active" and narrow.get("VpcPeeringConnectionId") == pcx, (
        f"the /24 must now be an ACTIVE route to the peering connection: {narrow!r}")

    l4, l4_s1_base, l4_s1_after = _blocked_leg(
        ssm, st, "s1", s1_ok=False, s2_ok=True,
        what="L4 with 10.141.0.0/16 -> internet gateway and 10.141.2.0/24 -> peering")
    assert l4["s2"]["body"] == st["nonce_s2"], (
        f"s2 must be reachable in L4, and it is covered ONLY by the /24 -> peering: the /16 over "
        f"it points at the internet gateway, so reaching s2 is possible only if the more specific "
        f"route wins. In L2 the specific route was the one that DROPPED and it also won, so "
        f"neither leg can be explained by a preference for a particular target: {l4['s2']!r}")
    assert l4["s1"]["body"] == "", (
        f"s1 is covered only by the /16 -> internet gateway in L4 and must be unreachable: "
        f"{l4['s1']!r}")
    assert int(l4_s1_after["hits"]) == int(l4_s1_base["hits"]), (
        f"s1's access log must not grow while the /16 sends its traffic to the internet gateway: "
        f"{l4_s1_base['hits']!r} -> {l4_s1_after['hits']!r}")
    l4_s2 = _server_view(ssm, st["s2"], st["client_ip"])
    assert int(l4_s2["hits"]) > int(after_l2_s2["hits"]), (
        f"s2's access log must record L4's request over the /24 -> peering: "
        f"{after_l2_s2['hits']!r} -> {l4_s2['hits']!r}")


# ===== in-band teardown =====================================================
def _teardown(ec2, iam, st, cause=None) -> None:
    """Ordered teardown: instances terminate before their gateways detach. Every step runs; an
    already-deleted resource counts as removed, and anything else that failed is raised at the
    end, naming the body's failure."""
    steps = []

    def _step(label, fn):
        steps.append((label, fn))

    # Instances first: they are the only thing here that bills by the second, and the internet
    # gateways cannot detach while a public address is still mapped in the VPC.
    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i))
    if st.get("pcx"):
        _step("pcx", lambda: ec2.delete_vpc_peering_connection(
            VpcPeeringConnectionId=st["pcx"]))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    for assoc in st.get("rt_assocs", []):
        _step(f"rt-assoc {assoc}", lambda a=assoc: ec2.disassociate_route_table(AssociationId=a))
    for rt in st.get("rts", []):
        _step(f"rt {rt}", lambda r=rt: _retry_dependency(
            lambda: ec2.delete_route_table(RouteTableId=r)))
    for igw, vpc in st.get("igws", []):
        _step(f"igw-detach {igw}", lambda g=igw, v=vpc: _retry_dependency(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=g, VpcId=v)))
        _step(f"igw {igw}", lambda g=igw: _retry_dependency(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=g)))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    for vpc in st.get("vpcs", []):
        _step(f"vpc {vpc}", lambda v=vpc: _retry_dependency(lambda: ec2.delete_vpc(VpcId=v)))
        _step(f"vpc-gone {vpc}", lambda v=vpc: _assert_vpc_gone(ec2, v))

    left = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES and not _pcx_gone(exc):
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 - collected, raised after every step has run
            left.append(f"{label}: {exc!r}")
    if left:
        raise AssertionError(
            f"teardown could not remove everything the check created: {left!r}"
            + (f" (after the check failed: {cause!r})" if cause is not None else "")
        ) from cause


def _net(fn):
    """A registered cleanup for a resource the in-band teardown may already have removed: an
    already-deleted resource counts as removed, every other failure raises."""
    def _call():
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES and not _pcx_gone(exc):
                raise
    return _call


def _assert_vpc_gone(ec2, vpc_id):
    still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    raise AssertionError(f"vpc {vpc_id} is still describable after delete: {still!r}")


_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidAssociationID.NotFound",
               "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
               "InvalidVpcPeeringConnectionID.NotFound", "InvalidRoute.NotFound")


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "droute-longest-prefix-match"},
            {"Key": "sim2real:managed", "Value": "true"}]


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
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


def _retry_dependency(fn, timeout_s=300, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterValue") \
                    and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _usable_zone(ec2):
    """An available AZ that offers the instance type; AZ names are per-account aliases, so a
    literal cannot be relied on."""
    offered = {o["Location"]
               for page in ec2.get_paginator("describe_instance_type_offerings").paginate(
                   LocationType="availability-zone",
                   Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])
               for o in page["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available availability zone offers {_INSTANCE_TYPE!r}; the offerings were "
        f"{sorted(offered)!r}")
    return usable[0]


def _create_vpc(ctx, ec2, st, cidr, tag_name):
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(tag_name)}],
    )["Vpc"]["VpcId"]
    st["vpcs"].append(vpc_id)
    ctx.on_cleanup(_net(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    return vpc_id


def _create_igw(ctx, ec2, st, vpc_id, tag_name):
    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(tag_name)}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(_net(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    st["igws"].append((igw, vpc_id))
    ctx.on_cleanup(_net(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)))
    return igw


def _create_subnet(ctx, ec2, st, vpc_id, cidr, zone, tag_name):
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(_net(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _create_rt(ctx, ec2, st, vpc_id, tag_name):
    rt = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(tag_name)}],
    )["RouteTable"]["RouteTableId"]
    st["rts"].append(rt)
    ctx.on_cleanup(_net(lambda: ec2.delete_route_table(RouteTableId=rt)))
    return rt


def _associate_rt(ctx, ec2, st, rt, subnet_id):
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet_id)["AssociationId"]
    st["rt_assocs"].append(assoc)
    ctx.on_cleanup(_net(lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    return assoc


def _create_sg(ctx, ec2, st, vpc_id, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(_net(lambda: ec2.delete_security_group(GroupId=sg)))
    return sg


def _pcx_gone(exc):
    """A prefix test: EC2 spells this id's "not found" code both `...ConnectionID.NotFound` and
    `...ConnectionId.NotFound`."""
    return _code(exc).startswith("InvalidVpcPeeringConnection")


def _pcx_status(ec2, pcx):
    try:
        got = ec2.describe_vpc_peering_connections(
            VpcPeeringConnectionIds=[pcx])["VpcPeeringConnections"]
    except ClientError as exc:
        if _pcx_gone(exc):
            return "gone"
        raise
    return got[0]["Status"]["Code"] if got else "gone"


def _routes(ec2, rt):
    return ec2.describe_route_tables(RouteTableIds=[rt])["RouteTables"][0]["Routes"]


def _route_or_none(ec2, rt, cidr):
    matches = [r for r in _routes(ec2, rt) if r.get("DestinationCidrBlock") == cidr]
    assert len(matches) <= 1, (
        f"a route table may hold at most one route for {cidr!r}; {rt!r} holds {matches!r}")
    return matches[0] if matches else None


def _route(ec2, rt, cidr):
    got = _route_or_none(ec2, rt, cidr)
    assert got is not None, (
        f"expected a route for {cidr!r} in {rt!r}; the table holds {_routes(ec2, rt)!r}")
    return got


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real droute longest-prefix-match",
                    Tags=[{"Key": "sim2real", "Value": "droute-longest-prefix-match"}])
    ctx.on_cleanup(_net(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_net(lambda: iam.detach_role_policy(RoleName=role_name,
                                                      PolicyArn=_SSM_CORE_POLICY)))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "droute-longest-prefix-match"}])
    ctx.on_cleanup(_net(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_net(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name)))
    # IAM exposes no "this profile is usable" condition to poll. `_launch`'s bounded retry on
    # InvalidParameterValue is what makes this correct; no sleep stands in for it.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(10):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 9:
                raise
            time.sleep(5)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
    for attempt in range(10):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "DeleteConflict" and attempt < 9:
                time.sleep(5)
                continue
            raise


def _server_user_data(nonce):
    return (
        "#!/bin/bash\n"
        "mkdir -p /tmp/srv\n"
        f"printf '%s' '{nonce}' > /tmp/srv/nonce\n"
        "cd /tmp/srv\n"
        f"nohup python3 -m http.server {_PORT} --bind 0.0.0.0 > /tmp/httpd.log 2>&1 &\n"
    )


def _launch(ctx, ec2, st, ami, subnet_id, sg_id, tag_name, user_data=None, private_ip=None):
    nic = {"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
           "AssociatePublicIpAddress": True}
    if private_ip:
        nic["PrivateIpAddress"] = private_ip
    kwargs = dict(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        NetworkInterfaces=[nic], IamInstanceProfile={"Name": st["profile"]},
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume")],
    )
    if user_data:
        kwargs["UserData"] = base64.b64encode(user_data.encode()).decode()
    iid = _call_with_retry(lambda: ec2.run_instances(**kwargs),
                           codes=_THROTTLE + ("InvalidParameterValue",),
                           retries=30, delay=5.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(_net(lambda: ec2.terminate_instances(InstanceIds=[iid])))
    return iid


def _wait_terminated(ec2, instance_id, timeout_s=420):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [i["State"]["Name"]
                  for r in _call_with_retry(
                      lambda: ec2.describe_instances(InstanceIds=[instance_id]),
                      codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                      retries=12, delay=5.0)["Reservations"]
                  for i in r["Instances"]]
        if all(s == "terminated" for s in states):
            return
        time.sleep(2)
    raise AssertionError(f"instance {instance_id} never reached terminated within {timeout_s}s")


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_phase(ssm, instance_id, script, timeout_s=300):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real droute lpm leg"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"invocation {command_id} reaching a terminal status")


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


def _client_script():
    """One invocation probes both servers, removing each body file first (curl truncates only once
    bytes arrive), and reads link-local IMDS as a liveness control no route table can affect."""
    return f"""python3 - <<'JEOF'
import json, os, subprocess
out = {{}}
for label, ip in (("s1", "{_S1_IP}"), ("s2", "{_S2_IP}")):
    path = "/tmp/body-" + label
    try:
        os.remove(path)
    except OSError:
        pass
    p = subprocess.run(
        ["curl", "-s", "-m", "8", "-o", path, "-w", "%{{http_code}}",
         "http://" + ip + ":{_PORT}/nonce"],
        capture_output=True, text=True)
    body = ""
    try:
        with open(path) as fh:
            body = fh.read()[:200]
    except OSError:
        pass
    out[label] = {{"rc": p.returncode, "code": p.stdout.strip(), "body": body}}
tok = subprocess.run(
    ["curl", "-s", "-m", "5", "-X", "PUT",
     "-H", "X-aws-ec2-metadata-token-ttl-seconds: 60",
     "http://169.254.169.254/latest/api/token"], capture_output=True, text=True)
iid = subprocess.run(
    ["curl", "-s", "-m", "5", "-H", "X-aws-ec2-metadata-token: " + tok.stdout.strip(),
     "http://169.254.169.254/latest/meta-data/instance-id"], capture_output=True, text=True)
out["imds"] = iid.stdout.strip()
print(json.dumps(out))
JEOF
"""


def _server_script(client_ip):
    return f"""python3 - <<'JEOF'
import json, subprocess
p = subprocess.run(["curl", "-s", "-m", "5", "http://127.0.0.1:{_PORT}/nonce"],
                   capture_output=True, text=True)
hits = 0
try:
    with open("/tmp/httpd.log") as fh:
        hits = sum(1 for line in fh if "{client_ip}" in line)
except OSError:
    pass
print(json.dumps({{"local": p.stdout.strip(), "hits": str(hits)}}))
JEOF
"""


def _server_view(ssm, instance_id, client_ip):
    return _json_line(_run_phase(ssm, instance_id, _server_script(client_ip)))


def _client_view(ssm, st):
    """One client invocation, asserting the command succeeded (it travels via the table's 0.0.0.0/0
    route) and that IMDS names the client instance."""
    inv = _run_phase(ssm, st["client"], _client_script())
    assert inv["ResponseCode"] == 0, (
        f"the control command itself failed on the client, so nothing it reported is evidence "
        f"about a route: rc={inv['ResponseCode']!r} stderr={inv.get('StandardErrorContent')!r}")
    got = _json_line(inv)
    assert got["imds"] == st["client"], (
        f"the guest must identify itself as {st['client']!r} through link-local IMDS, which no "
        f"route table can affect; it reported {got['imds']!r}, so the verdicts in the same payload "
        f"are not trustworthy")
    return got


def _probe(ssm, st, s1_ok, s2_ok, what):
    """Poll the client until the expected reachability pair holds, so an unconverged route change is
    retried and one that never converges fails naming what was last seen."""
    def _ok(r):
        return (r["s1"]["rc"] == 0) is s1_ok and (r["s2"]["rc"] == 0) is s2_ok

    return _poll(lambda: _client_view(ssm, st), _ok, timeout_s=300, interval_s=5.0, what=what)


def _blocked_leg(ssm, st, blocked, s1_ok, s2_ok, what):
    """Converge to the expected pair, then prove one more attempt leaves the blocked server's log
    untouched; the baseline is taken after convergence because earlier attempts may have arrived."""
    first = _probe(ssm, st, s1_ok=s1_ok, s2_ok=s2_ok, what=what)
    assert first[blocked]["rc"] == _CURL_TIMEOUT, (
        f"a DROPPED packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7) and not fail some other way: {first[blocked]!r} for {what}")
    base = _server_view(ssm, st[blocked], st["client_ip"])
    again = _client_view(ssm, st)
    assert again[blocked]["rc"] == _CURL_TIMEOUT, (
        f"a second identical attempt must be dropped too, or the block was a transient: "
        f"{again[blocked]!r} for {what}")
    return again, base, _server_view(ssm, st[blocked], st["client_ip"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
