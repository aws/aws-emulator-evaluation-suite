"""droute-deleted-peering-target-blackholes-the-route-and-drops-traffic."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "droute-deleted-peering-target-blackholes-the-route-and-drops-traffic"
GROUP = "route-table-data-plane"
SERVICES = ["ec2"]

_CLIENT_VPC_CIDR = "10.142.0.0/16"
_CLIENT_SUBNET_CIDR = "10.142.1.0/24"
_PEER_VPC_CIDR = "10.143.0.0/16"
_SERVER_SUBNET_CIDR = "10.143.1.0/24"
_SERVER_IP = "10.143.1.10"
_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
#: curl(1) exit statuses. 28 is "Operation timeout" -- a packet that was silently DROPPED. 7 is
#: "Failed to connect", which is what a REFUSED connection (an RST) looks like. A blackhole route
#: must produce 28: the whole claim is that the bytes go nowhere and nothing answers.
_CURL_TIMEOUT = 28


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Deleting a peering target leaves its route as State blackhole on both sides, and matching
    packets are dropped (curl timeout, no server log) rather than falling through to 0.0.0.0/0;
    ReplaceRoute to a new peering restores delivery."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "instances": [], "rts": [], "rt_assocs": [],
                "igws": [], "vpcs": [], "pcxs": [], "role": None, "profile": None, "ctx": ctx}
    try:
        _build(ctx, ec2, ssm, iam, st)
        _legs(ctx, ec2, ssm, st)
    finally:
        st["leftovers"] = _teardown(ec2, iam, st)
    assert st["leftovers"] == [], (
        f"teardown could not remove everything the check created: {st['leftovers']!r}"
    )


# ===== the estate ===========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-droute-bh-")
    st["name"] = name
    st["nonce"] = name + "-srv"

    # Every decidable precondition ahead of the first create: an AZ that cannot run the instance
    # type is an answer available now, and finding it out after two launches bills for nothing.
    zone = _usable_zone(ec2)

    vpc_a = _create_vpc(ctx, ec2, st, _CLIENT_VPC_CIDR, name + "-client-vpc")
    vpc_b = _create_vpc(ctx, ec2, st, _PEER_VPC_CIDR, name + "-peer-vpc")
    st["vpc_a"], st["vpc_b"] = vpc_a, vpc_b

    igw_a = _create_igw(ctx, ec2, st, vpc_a, name + "-client-igw")
    igw_b = _create_igw(ctx, ec2, st, vpc_b, name + "-peer-igw")

    client_subnet = _create_subnet(ctx, ec2, st, vpc_a, _CLIENT_SUBNET_CIDR, zone,
                                   name + "-client-subnet")
    server_subnet = _create_subnet(ctx, ec2, st, vpc_b, _SERVER_SUBNET_CIDR, zone,
                                   name + "-server-subnet")

    # The route table under test: a CUSTOM one associated with the client subnet, so nothing
    # outside this check can be affected by a leg and the VPC's main table is never mutated. The
    # `0.0.0.0/0` entry stays untouched throughout, and is what makes L2's drop meaningful: a
    # blackholed /16 must NOT fall through to it.
    rt_a = _create_rt(ctx, ec2, st, vpc_a, name + "-client-rt")
    st["rt_a"] = rt_a
    ec2.create_route(RouteTableId=rt_a, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_a)
    _associate_rt(ctx, ec2, st, rt_a, client_subnet)

    rt_b = _create_rt(ctx, ec2, st, vpc_b, name + "-peer-rt")
    st["rt_b"] = rt_b
    ec2.create_route(RouteTableId=rt_b, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_b)
    _associate_rt(ctx, ec2, st, rt_b, server_subnet)

    sg_client = _create_sg(ctx, ec2, st, vpc_a, name + "-client-sg", "sim2real droute bh client")
    sg_server = _create_sg(ctx, ec2, st, vpc_b, name + "-server-sg", "sim2real droute bh server")
    ec2.authorize_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": _CLIENT_VPC_CIDR}]}])

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    st["server"] = _launch(ctx, ec2, st, ami, server_subnet, sg_server, name + "-server",
                           user_data=_server_user_data(st["nonce"]), private_ip=_SERVER_IP)
    st["client"] = _launch(ctx, ec2, st, ami, client_subnet, sg_client, name + "-client")

    for label, iid in (("server", st["server"]), ("client", st["client"])):
        info = _poll(lambda iid=iid: _agent_view(ssm, iid),
                     lambda i: i is not None and i.get("PingStatus") == "Online",
                     timeout_s=600, interval_s=2, ctx=ctx,
                     what=f"the SSM agent on the {label} {iid} coming Online")
        assert info["PingStatus"] == "Online", f"the {label}'s agent view was {info!r}"

    # RunInstances is eventually consistent: DescribeInstances can 404 an id it just minted.
    described = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=[st["server"], st["client"]]),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=30, delay=2.0)["Reservations"]
    by_id = {i["InstanceId"]: i for r in described for i in r["Instances"]}
    assert by_id[st["server"]]["PrivateIpAddress"] == _SERVER_IP, (
        f"the server did not take the address the legs target: "
        f"{by_id[st['server']]['PrivateIpAddress']!r}, expected {_SERVER_IP!r}")
    st["client_ip"] = by_id[st["client"]]["PrivateIpAddress"]

    # The barrier: nothing below is interpretable unless the server actually serves.
    view = _poll(lambda: _server_view(ssm, st["server"], st["client_ip"], ctx=st["ctx"]),
                 lambda v: v["local"] == st["nonce"], timeout_s=300, interval_s=2, ctx=ctx,
                 what=f"the server answering its own listener on 127.0.0.1 with {st['nonce']!r}")
    assert view["local"] == st["nonce"], (
        f"the server must serve its own nonce before any leg runs; it returned {view!r}")


# ===== the three legs =======================================================
def _legs(ctx, ec2, ssm, st) -> None:
    rt_a, rt_b = st["rt_a"], st["rt_b"]

    # --- L1: a live peering connection, reachable ----------------------------
    pcx1 = _peer(ctx, ec2, st)
    ec2.create_route(RouteTableId=rt_a, DestinationCidrBlock=_PEER_VPC_CIDR,
                     VpcPeeringConnectionId=pcx1)
    ec2.create_route(RouteTableId=rt_b, DestinationCidrBlock=_CLIENT_VPC_CIDR,
                     VpcPeeringConnectionId=pcx1)
    live = _route(ec2, rt_a, _PEER_VPC_CIDR)
    assert live["State"] == "active", f"the route must start ACTIVE: {live!r}"
    assert live.get("VpcPeeringConnectionId") == pcx1, (
        f"the route must target the peering connection {pcx1!r}: {live!r}")
    default = _route(ec2, rt_a, "0.0.0.0/0")
    assert default["State"] == "active", (
        f"the default route must be active for the whole check, because L2's claim is that a "
        f"blackholed /16 does NOT fall through to it: {default!r}")

    l1 = _probe(ssm, st, expect_ok=True, what="L1 with the /16 -> a live peering connection")
    assert l1["srv"]["body"] == st["nonce"], (
        f"L1 must reach the server over the peering connection and get the server's own nonce: "
        f"{l1['srv']!r}")
    base = _server_view(ssm, st["server"], st["client_ip"], ctx=st["ctx"])
    assert int(base["hits"]) > 0, (
        f"the server must have logged L1's request from {st['client_ip']!r}: {base!r}")

    # --- L2: delete the TARGET; the route survives as a blackhole ------------
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx1)
    _poll(lambda: _pcx_status(ec2, pcx1), lambda s: s in ("deleted", "gone"),
          timeout_s=300, interval_s=2, ctx=ctx,
          what=f"peering connection {pcx1} reporting deleted")

    dead = _poll(lambda: _route(ec2, rt_a, _PEER_VPC_CIDR),
                 lambda r: r["State"] == "blackhole", timeout_s=300, interval_s=2, ctx=ctx,
                 what=f"the {_PEER_VPC_CIDR} route in {rt_a} becoming blackhole")
    assert dead["State"] == "blackhole", (
        f"deleting the target must leave the route in state blackhole, not remove it: {dead!r}")
    assert dead.get("VpcPeeringConnectionId") == pcx1, (
        f"the blackholed route must still NAME the deleted peering connection {pcx1!r} -- a route "
        f"that silently lost its target is a different and weaker contract: {dead!r}")
    peer_side = _poll(lambda: _route(ec2, rt_b, _CLIENT_VPC_CIDR),
                      lambda r: r["State"] == "blackhole", timeout_s=300, interval_s=2, ctx=ctx,
                      what=f"the {_CLIENT_VPC_CIDR} route in {rt_b} becoming blackhole")
    assert peer_side.get("VpcPeeringConnectionId") == pcx1, (
        f"the peer VPC's return route must blackhole too, still naming {pcx1!r}: {peer_side!r}")
    assert _route(ec2, rt_a, "0.0.0.0/0")["State"] == "active", (
        f"only the route whose target died may change state; the default route must be untouched: "
        f"{_routes(ec2, rt_a)!r}")

    blocked, bh_base, bh_after = _blocked_leg(
        ssm, st, what="L2 with the /16 blackholed by the deletion of its peering connection")
    assert blocked["srv"]["body"] == "", (
        f"a blackhole DROPS the packet: nothing may answer, and in particular the packet must not "
        f"fall through to the still-active 0.0.0.0/0 route: {blocked['srv']!r}")
    assert int(bh_after["hits"]) == int(bh_base["hits"]), (
        f"the server's own access log must not grow across one further attempt while the route is "
        f"blackholed: {bh_base['hits']!r} -> {bh_after['hits']!r}")
    assert bh_after["local"] == st["nonce"], (
        f"the server must still answer its own listener, or L2 is evidence about a dead host "
        f"rather than about a blackhole: {bh_after!r}")

    # --- L3: point the same destination at a live target again ---------------
    pcx2 = _peer(ctx, ec2, st)
    assert pcx2 != pcx1, f"the replacement peering connection must be a new one: {pcx2!r}"
    ec2.replace_route(RouteTableId=rt_a, DestinationCidrBlock=_PEER_VPC_CIDR,
                      VpcPeeringConnectionId=pcx2)
    ec2.replace_route(RouteTableId=rt_b, DestinationCidrBlock=_CLIENT_VPC_CIDR,
                      VpcPeeringConnectionId=pcx2)
    revived = _poll(lambda: _route(ec2, rt_a, _PEER_VPC_CIDR),
                    lambda r: r["State"] == "active", timeout_s=300, interval_s=2, ctx=ctx,
                    what=f"the {_PEER_VPC_CIDR} route in {rt_a} returning to active")
    assert revived.get("VpcPeeringConnectionId") == pcx2, (
        f"the revived route must name the REPLACEMENT peering connection {pcx2!r}: {revived!r}")

    l3 = _probe(ssm, st, expect_ok=True,
                what="L3 after ReplaceRoute pointed the same destination at a live peering")
    assert l3["srv"]["body"] == st["nonce"], (
        f"replacing the dead target must restore delivery to the same server: {l3['srv']!r}")
    after = _server_view(ssm, st["server"], st["client_ip"], ctx=st["ctx"])
    assert int(after["hits"]) > int(bh_after["hits"]), (
        f"L3's request must reach the server and be logged, closing the bracket around L2's "
        f"absence: {bh_after['hits']!r} -> {after['hits']!r}")


# ===== in-band teardown =====================================================
def _teardown(ec2, iam, st) -> list:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Returns what
    it could not remove, so a leak is asserted rather than hoped away. Never raises: it runs in a
    `finally` and must not mask the failure the check found."""
    left = []

    def _step(label, fn):
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES and not _pcx_gone(exc):
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 - reported through `left`, never propagated
            left.append(f"{label}: {exc!r}")

    # Instances first: they are the only thing here that bills by the second, and the internet
    # gateways cannot detach while a public address is still mapped in the VPC.
    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i))
    for pcx in st.get("pcxs", []):
        _step(f"pcx {pcx}", lambda p=pcx: ec2.delete_vpc_peering_connection(
            VpcPeeringConnectionId=p))
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
        try:
            still = ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"]
            left.append(f"vpc {vpc} is still describable: {still!r}")
        except ClientError as exc:
            if _code(exc) != "InvalidVpcID.NotFound":
                left.append(f"vpc {vpc} describe returned {_code(exc)!r}")
    return left


_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidAssociationID.NotFound",
               "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
               "InvalidRoute.NotFound")


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _pcx_gone(exc):
    """A prefix test, not a code alternation: EC2 spells this id's "not found" code two ways
    across its own documentation (`...ConnectionID.NotFound` and `...ConnectionId.NotFound`), and
    picking one would turn a gone peering connection into an unhandled raise in teardown."""
    return _code(exc).startswith("InvalidVpcPeeringConnection")


def _unless_gone(fn, *codes):
    """A backup cleanup the in-band teardown may already have done: only *codes* (the resource's
    own not-found) count as done; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "droute-blackhole"},
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=2.0, what="", ctx=None):
    """Poll until predicate holds; with ctx the bound is capped by the runner's remaining time."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s:.0f}s (last observed: {last!r})")
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
    """Derive an AZ that offers the instance type: an AWS-picked zone need not, and AZ names are
    per-account aliases, so a literal is no safer. Empty means this region cannot run it."""
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
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    return vpc_id


def _create_igw(ctx, ec2, st, vpc_id, tag_name):
    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(tag_name)}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw),
        "InvalidInternetGatewayID.NotFound"))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    st["igws"].append((igw, vpc_id))
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id),
        "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached"))
    return igw


def _create_subnet(ctx, ec2, st, vpc_id, cidr, zone, tag_name):
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))
    return subnet_id


def _create_rt(ctx, ec2, st, vpc_id, tag_name):
    rt = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(tag_name)}],
    )["RouteTable"]["RouteTableId"]
    st["rts"].append(rt)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_route_table(RouteTableId=rt), "InvalidRouteTableID.NotFound"))
    return rt


def _associate_rt(ctx, ec2, st, rt, subnet_id):
    assoc = ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet_id)["AssociationId"]
    st["rt_assocs"].append(assoc)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.disassociate_route_table(AssociationId=assoc), "InvalidAssociationID.NotFound"))
    return assoc


def _create_sg(ctx, ec2, st, vpc_id, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_security_group(GroupId=sg), "InvalidGroup.NotFound"))
    return sg


def _peer(ctx, ec2, st):
    """Create, accept and wait for one peering connection between the two VPCs this check built."""
    pcx = ec2.create_vpc_peering_connection(
        VpcId=st["vpc_a"], PeerVpcId=st["vpc_b"],
        TagSpecifications=[{"ResourceType": "vpc-peering-connection",
                            "Tags": _tags_for(st["name"] + "-pcx")}],
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    st["pcxs"].append(pcx)
    ctx.on_cleanup(lambda: _delete_pcx_if_live(ec2, pcx))
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "pending-acceptance",
          timeout_s=180, interval_s=2, ctx=ctx,
          what=f"peering connection {pcx} reaching pending-acceptance")
    _call_with_retry(lambda: ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx))
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "active",
          timeout_s=180, interval_s=2, ctx=ctx,
          what=f"peering connection {pcx} becoming active")
    return pcx


def _pcx_status(ec2, pcx):
    try:
        got = ec2.describe_vpc_peering_connections(
            VpcPeeringConnectionIds=[pcx])["VpcPeeringConnections"]
    except ClientError as exc:
        if _pcx_gone(exc):
            return "gone"
        raise
    return got[0]["Status"]["Code"] if got else "gone"


def _delete_pcx_if_live(ec2, pcx):
    """A backup delete: a connection the in-band teardown already deleted refuses a second delete
    with InvalidStateTransition, which is not a leak; anything still live is deleted for real."""
    if _pcx_status(ec2, pcx) in ("gone", "deleted", "deleting", "rejected", "failed", "expired"):
        return
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)


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
                    Description="sim2real droute blackhole",
                    Tags=[{"Key": "sim2real", "Value": "droute-blackhole"}])
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY),
        "NoSuchEntity"))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "droute-blackhole"}])
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name), "NoSuchEntity"))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name),
        "NoSuchEntity"))
    # IAM exposes no "this profile is usable" condition to poll. `_launch`'s bounded retry on
    # InvalidParameterValue is what makes this correct; no sleep stands in for it.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(25):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 24:
                raise
            time.sleep(2)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
    for attempt in range(25):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "DeleteConflict" and attempt < 24:
                time.sleep(2)
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
                           retries=75, delay=2.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[iid]))
    return iid


def _wait_terminated(ec2, instance_id, timeout_s=420):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [i["State"]["Name"]
                  for r in _call_with_retry(
                      lambda: ec2.describe_instances(InstanceIds=[instance_id]),
                      codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                      retries=30, delay=2.0)["Reservations"]
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


def _run_phase(ssm, instance_id, script, timeout_s=300, ctx=None):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real droute blackhole leg"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=1.0, ctx=ctx,
                 what=f"invocation {command_id} reaching a terminal status")


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


def _client_script():
    """The body file is removed first: curl truncates it only once bytes arrive, so a timed-out leg
    would otherwise report the previous body. IMDSv2 is read as a link-local liveness control."""
    return f"""python3 - <<'JEOF'
import json, os, subprocess
path = "/tmp/body-srv"
try:
    os.remove(path)
except OSError:
    pass
p = subprocess.run(
    ["curl", "-s", "--connect-timeout", "2", "-m", "8", "-o", path, "-w", "%{{http_code}}",
     "http://{_SERVER_IP}:{_PORT}/nonce"],
    capture_output=True, text=True)
body = ""
try:
    with open(path) as fh:
        body = fh.read()[:200]
except OSError:
    pass
tok = subprocess.run(
    ["curl", "-s", "-m", "5", "-X", "PUT",
     "-H", "X-aws-ec2-metadata-token-ttl-seconds: 60",
     "http://169.254.169.254/latest/api/token"], capture_output=True, text=True)
iid = subprocess.run(
    ["curl", "-s", "-m", "5", "-H", "X-aws-ec2-metadata-token: " + tok.stdout.strip(),
     "http://169.254.169.254/latest/meta-data/instance-id"], capture_output=True, text=True)
print(json.dumps({{"srv": {{"rc": p.returncode, "code": p.stdout.strip(), "body": body}},
                  "imds": iid.stdout.strip()}}))
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


def _server_view(ssm, instance_id, client_ip, ctx=None):
    return _json_line(_run_phase(ssm, instance_id, _server_script(client_ip), ctx=ctx))


def _client_view(ssm, st):
    """One client invocation, with both in-guest controls asserted. The SSM command travels via the
    same table's 0.0.0.0/0 entry, so its success proves the table still forwards other traffic."""
    inv = _run_phase(ssm, st["client"], _client_script(), ctx=st["ctx"])
    assert inv["ResponseCode"] == 0, (
        f"the control command itself failed on the client, so nothing it reported is evidence "
        f"about a route: rc={inv['ResponseCode']!r} stderr={inv.get('StandardErrorContent')!r}")
    got = _json_line(inv)
    assert got["imds"] == st["client"], (
        f"the guest must identify itself as {st['client']!r} through link-local IMDS, which no "
        f"route table can affect; it reported {got['imds']!r}, so the verdict in the same payload "
        f"is not trustworthy")
    return got


def _probe(ssm, st, expect_ok, what):
    """Drive one leg from the client and poll until the expected outcome, so a route change that
    has not converged yet is a retry and one that never converges is a FAIL naming what was last
    seen."""
    return _poll(lambda: _client_view(ssm, st),
                 lambda r: (r["srv"]["rc"] == 0) is expect_ok,
                 timeout_s=300, interval_s=2.0, what=what, ctx=st["ctx"])


def _blocked_leg(ssm, st, what):
    """Converge to blocked, then prove one more attempt leaves the server's access log untouched.
    The baseline is taken after convergence because pre-blackhole attempts do get logged."""
    first = _probe(ssm, st, expect_ok=False, what=what)
    assert first["srv"]["rc"] == _CURL_TIMEOUT, (
        f"a blackholed packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7) and not fail some other way: {first['srv']!r} for {what}")
    base = _server_view(ssm, st["server"], st["client_ip"], ctx=st["ctx"])
    again = _client_view(ssm, st)
    assert again["srv"]["rc"] == _CURL_TIMEOUT, (
        f"a second identical attempt must be dropped too, or the blackhole was a transient: "
        f"{again['srv']!r} for {what}")
    return again, base, _server_view(ssm, st["server"], st["client_ip"], ctx=st["ctx"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
