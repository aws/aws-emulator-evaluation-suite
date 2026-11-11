"""dtgw-transit-gateway-forwards-packets-between-two-vpcs-and-a-blackholed-route-stops-them."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dtgw-transit-gateway-forwards-packets-between-two-vpcs-and-a-blackholed-route-stops-them"
GROUP = "data-plane"
SERVICES = ["ec2", "ssm"]

_VPC_A_CIDR = "10.60.0.0/16"
_VPC_B_CIDR = "10.61.0.0/16"
_SUBNET_A_CIDR = "10.60.1.0/24"
_SUBNET_B_CIDR = "10.61.1.0/24"
_SERVER_IP = "10.61.1.10"
_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates",
             "IncorrectState")
# A packet the transit gateway drops leaves the client's SYN unanswered (`socket.timeout`); one that
# reaches a host with no listener gets an RST (ConnectionRefusedError). Only the first proves the
# transit gateway made the decision, so every blocked leg asserts `kind == "timeout"`.
_DROPPED = "timeout"
_CONNECTED = "connected"


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A transit gateway forwards TCP between two VPCs (the far host logs the client's private IP);
    blackholing or deleting the forward route, or blackholing only the return route, stops the
    traffic while both guests stay healthy, and restoring each route resumes it.

    Reference: https://docs.aws.amazon.com/vpc/latest/tgw/tgw-route-tables.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"vpcs": [], "subnets": [], "igws": [], "rtbs": [], "sgs": [], "instances": [],
                "attachments": [], "tgw": None, "assocs": []}
    try:
        _build(ctx, ec2, ssm, iam, st)
        _legs(ec2, ssm, st, ctx=ctx)
    finally:
        st["leftovers"] = _teardown(ec2, iam, st, ctx=ctx)
    assert st["leftovers"] == [], (
        f"teardown could not remove everything the check created: {st['leftovers']!r}"
    )


def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-dtgw-")
    st["name"], st["nonce"] = name, name

    # Decidable before anything is created: an AZ that both offers the instance type and is
    # actually available. An empty intersection means this region cannot run the check at all.
    zones = _usable_zones(ec2, want=1)
    az = zones[0]
    st["az"] = az

    vpc_a, subnet_a, rtb_a = _vpc(ctx, ec2, st, _VPC_A_CIDR, _SUBNET_A_CIDR, az, name + "-a")
    vpc_b, subnet_b, rtb_b = _vpc(ctx, ec2, st, _VPC_B_CIDR, _SUBNET_B_CIDR, az, name + "-b")
    st.update(vpc_a=vpc_a, subnet_a=subnet_a, rtb_a=rtb_a,
              vpc_b=vpc_b, subnet_b=subnet_b, rtb_b=rtb_b)

    sg_a = _create_sg(ctx, ec2, st, vpc_a, name + "-client", "sim2real dtgw client")
    sg_b = _create_sg(ctx, ec2, st, vpc_b, name + "-server", "sim2real dtgw server")
    # The only ingress names the peer VPC's CIDR, so a connecting leg can only have crossed the
    # transit gateway.
    ec2.authorize_security_group_ingress(
        GroupId=sg_b,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": _VPC_A_CIDR}]}])
    admitted = ec2.describe_security_groups(GroupIds=[sg_b])["SecurityGroups"][0]["IpPermissions"]
    assert len(admitted) == 1 and [r["CidrIp"] for r in admitted[0]["IpRanges"]] == [_VPC_A_CIDR], (
        f"the server must admit tcp/{_PORT} from {_VPC_A_CIDR!r} and nothing else, or a leg that "
        f"connects proves nothing about the path it took; it admits {admitted!r}")

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    # The transit gateway and SSM registration both take minutes, so both start before either wait.
    st["tgw"] = _create_tgw(ctx, ec2, st, name)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    server_user_data = (
        "#!/bin/bash\n"
        "mkdir -p /tmp/srv\n"
        f"printf '%s' '{st['nonce']}' > /tmp/srv/nonce\n"
        "cd /tmp/srv\n"
        f"nohup python3 -m http.server {_PORT} --bind 0.0.0.0 > /tmp/httpd.log 2>&1 &\n"
    )
    st["server"] = _launch(ctx, ec2, st, ami, subnet_b, sg_b, name + "-server",
                           user_data=server_user_data, private_ip=_SERVER_IP)
    st["client"] = _launch(ctx, ec2, st, ami, subnet_a, sg_a, name + "-client")

    tgw_view = _poll(
        lambda: ec2.describe_transit_gateways(
            TransitGatewayIds=[st["tgw"]])["TransitGateways"][0],
        lambda t: t["State"] == "available", timeout_s=600, interval_s=2,
        what=f"transit gateway {st['tgw']!r} becoming available", ctx=ctx)
    opts = tgw_view["Options"]
    assert opts["DefaultRouteTablePropagation"] == "disable", (
        f"the transit gateway must not propagate routes automatically, or the forwarding table is "
        f"not the one this check wrote: {opts!r}")
    rtb = opts["AssociationDefaultRouteTableId"]
    st["tgw_rtb"] = rtb

    att_a = _attach(ctx, ec2, st, vpc_a, subnet_a, name + "-a")
    att_b = _attach(ctx, ec2, st, vpc_b, subnet_b, name + "-b")
    st["att_a"], st["att_b"] = att_a, att_b
    for label, att in (("a", att_a), ("b", att_b)):
        state = _poll(lambda att=att: _attachment_state(ec2, att),
                      lambda s: s == "available", timeout_s=900, interval_s=2,
                      what=f"vpc attachment {att!r} for vpc {label} becoming available", ctx=ctx)
        assert state == "available", f"attachment {att!r} settled at {state!r}"
    associated = {a["TransitGatewayAttachmentId"]: a["State"]
                  for a in _route_table_associations(ec2, rtb)}
    assert associated.get(att_a) == "associated" and associated.get(att_b) == "associated", (
        f"both attachments must be associated with {rtb!r} so their lookups use the table this "
        f"check writes; the table reports {associated!r}")

    # Every route in the transit gateway's table is a static one written here.
    _put_route(ec2, rtb, _VPC_A_CIDR, att_a)
    _put_route(ec2, rtb, _VPC_B_CIDR, att_b)
    for cidr in (_VPC_A_CIDR, _VPC_B_CIDR):
        _await_route(ec2, rtb, cidr, lambda r: r is not None and r["State"] == "active",
                     f"the static route for {cidr!r} becoming visible and active", ctx=ctx)

    # The VPC side sends the peer CIDR to the transit gateway; re-asserted inside every blocked leg.
    for rtb_id, peer in ((rtb_a, _VPC_B_CIDR), (rtb_b, _VPC_A_CIDR)):
        ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock=peer,
                         TransitGatewayId=st["tgw"])
        route = _vpc_route(ec2, rtb_id, peer)
        assert route is not None and route["State"] == "active", (
            f"the route for {peer!r} in {rtb_id!r} did not come up: {route!r}")
        assert route.get("TransitGatewayId") == st["tgw"], (
            f"the route for {peer!r} in {rtb_id!r} must target {st['tgw']!r}: {route!r}")

    for label, iid in (("server", st["server"]), ("client", st["client"])):
        info = _poll(lambda iid=iid: _agent_view(ssm, iid),
                     lambda i: i is not None and i.get("PingStatus") == "Online",
                     timeout_s=900, interval_s=2,
                     what=f"the SSM agent on the {label} {iid} coming Online over its public "
                          f"address", ctx=ctx)
        assert info["PingStatus"] == "Online", f"the {label}'s agent view was {info!r}"

    described = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=[st["server"], st["client"]]),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=30, delay=2.0)["Reservations"]
    by_id = {i["InstanceId"]: i for r in described for i in r["Instances"]}
    assert by_id[st["server"]]["PrivateIpAddress"] == _SERVER_IP, (
        f"the server did not take the fixed address the legs target: "
        f"{by_id[st['server']]['PrivateIpAddress']!r}")
    assert by_id[st["server"]]["VpcId"] == vpc_b and by_id[st["client"]]["VpcId"] == vpc_a, (
        f"the two instances must sit in the two different VPCs the transit gateway joins: "
        f"{by_id[st['server']]['VpcId']!r} and {by_id[st['client']]['VpcId']!r}")
    st["client_ip"] = by_id[st["client"]]["PrivateIpAddress"]
    assert st["client_ip"].startswith("10.60."), (
        f"the client must hold an address inside {_VPC_A_CIDR!r}, since the server's security "
        f"group admits only that range: {st['client_ip']!r}")


def _legs(ec2, ssm, st, *, ctx) -> None:
    rtb, att_b = st["tgw_rtb"], st["att_b"]

    # Polled, because the SSM agent and the user-data HTTP server come up independently.
    local = _poll(lambda: _server_view(ssm, st, ctx=ctx),
                  lambda v: st["nonce"] in v["local"], timeout_s=300, interval_s=2,
                  what="the server answering its own listener on 127.0.0.1 with the nonce", ctx=ctx)
    assert st["nonce"] in local["local"], (
        f"the server must answer its own listener on 127.0.0.1 before any leg runs; it returned "
        f"{local['local']!r}, which does not carry {st['nonce']!r}")
    hits = int(local["hits"])
    assert hits == 0, (
        f"before the first leg the server's access log must hold no request from the client "
        f"{st['client_ip']!r}, or the baseline is somebody else's traffic: {local!r}")

    # L1: the packets cross.
    l1 = _reach(ssm, st, expect_ok=True, what="L1 with static routes for both CIDRs", ctx=ctx)
    peer = l1["peer_vpc"]
    assert peer["kind"] == _CONNECTED, f"L1 did not connect to the server: {l1!r}"
    assert st["nonce"] in peer["body"], (
        f"L1 connected but did not read the server's own payload {st['nonce']!r}: {peer!r}")
    assert peer["peer"] == st["client_ip"], (
        f"L1's connection must be sourced at the client's private address {st['client_ip']!r}, "
        f"not at anything a NAT rewrote: {peer!r}")
    assert peer["body_error"] == "", (
        f"L1 must read the whole response, not stall part way through it: {peer!r}")
    after1 = _server_view(ssm, st, ctx=ctx)
    hits1 = int(after1["hits"])
    assert hits1 > hits, (
        f"the FAR END must record L1's request, sourced at {st['client_ip']!r}: "
        f"{hits!r} -> {hits1!r} ({after1!r})")
    assert '"GET /nonce HTTP/1.0" 200' in after1["last"][-1], (
        f"the server's own access log must show it served the request it received over the "
        f"transit gateway: {after1['last']!r}")

    # L2: the forward route blackholed.
    blackholed = _replace_route(ec2, rtb, _VPC_B_CIDR, blackhole=True)
    assert blackholed["State"] == "blackhole" and blackholed["Type"] == "static", (
        f"the forward route must report itself blackholed: {blackholed!r}")
    assert "TransitGatewayAttachments" not in blackholed, (
        f"a blackholed route names no attachment to forward to: {blackholed!r}")
    _await_route(ec2, rtb, _VPC_B_CIDR, lambda r: r is not None and r["State"] == "blackhole",
                 f"the route for {_VPC_B_CIDR!r} reporting blackhole in the route table", ctx=ctx)
    l2, after2 = _blocked_leg(ec2, ssm, st, hits1,
                              what="L2 with the forward route blackholed", ctx=ctx)
    assert l2["peer_vpc"]["body"] == "", (
        f"L2 read a body, so something answered: {l2!r}")

    # L3: point it back at the attachment.
    restored = _replace_route(ec2, rtb, _VPC_B_CIDR, attachment=att_b)
    assert restored["State"] == "active", f"L3 did not restore the route: {restored!r}"
    hits3 = _resumes(ssm, st, int(after2["hits"]),
                     what="L3 after the forward route was pointed back at the attachment", ctx=ctx)

    # L4: the forward route deleted outright.
    ec2.delete_transit_gateway_route(TransitGatewayRouteTableId=rtb,
                                     DestinationCidrBlock=_VPC_B_CIDR)
    _await_route(ec2, rtb, _VPC_B_CIDR, lambda r: r is None,
                 f"the route for {_VPC_B_CIDR!r} disappearing from the route table", ctx=ctx)
    still_there = _tgw_route(ec2, rtb, _VPC_A_CIDR)
    assert still_there is not None and still_there["State"] == "active", (
        f"only the forward route may be gone; the return route for {_VPC_A_CIDR!r} must still be "
        f"active, or L4 breaks two things at once: {still_there!r}")
    l4, after4 = _blocked_leg(ec2, ssm, st, hits3,
                              what="L4 with the forward route deleted", ctx=ctx)
    assert l4["peer_vpc"]["body"] == "", f"L4 read a body, so something answered: {l4!r}"

    # L5: recreate it.
    recreated = _put_route(ec2, rtb, _VPC_B_CIDR, att_b)
    assert recreated["State"] == "active", f"L5 did not recreate the route: {recreated!r}"
    _await_route(ec2, rtb, _VPC_B_CIDR, lambda r: r is not None and r["State"] == "active",
                 f"the recreated route for {_VPC_B_CIDR!r} becoming active again", ctx=ctx)
    hits5 = _resumes(ssm, st, int(after4["hits"]),
                     what="L5 after the forward route was recreated", ctx=ctx)

    # L6: the return route only; the request leaves but the handshake can never complete.
    back = _replace_route(ec2, rtb, _VPC_A_CIDR, blackhole=True)
    assert back["State"] == "blackhole", f"L6 did not blackhole the return route: {back!r}"
    forward = _tgw_route(ec2, rtb, _VPC_B_CIDR)
    assert forward is not None and forward["State"] == "active", (
        f"the FORWARD route must stay active through L6 -- the whole leg is that the return "
        f"direction is a separate lookup: {forward!r}")
    _await_route(ec2, rtb, _VPC_A_CIDR, lambda r: r is not None and r["State"] == "blackhole",
                 f"the return route for {_VPC_A_CIDR!r} reporting blackhole", ctx=ctx)
    l6, after6 = _blocked_leg(ec2, ssm, st, hits5,
                              what="L6 with only the RETURN route blackholed", ctx=ctx)
    assert l6["peer_vpc"]["body"] == "", f"L6 read a body, so something answered: {l6!r}"

    # L7: restore.
    healed = _replace_route(ec2, rtb, _VPC_A_CIDR, attachment=st["att_a"])
    assert healed["State"] == "active", f"L7 did not restore the return route: {healed!r}"
    _resumes(ssm, st, int(after6["hits"]),
             what="L7 after the return route was pointed back at the attachment", ctx=ctx)


def _blocked_leg(ec2, ssm, st, hits_before, what, *, ctx):
    """Converge to blocked, then prove one more attempt leaves the far end's access log untouched.

    The baseline is taken after convergence, because attempts made before the route change took
    effect do cross; both guests must stay healthy."""
    first = _reach(ssm, st, expect_ok=False, what=what, ctx=ctx)
    assert first["peer_vpc"]["kind"] == _DROPPED, (
        f"a DROPPED packet must time the guest's connect out ({_DROPPED!r}), not come back "
        f"refused: {first['peer_vpc']!r} for {what}")
    base = _server_view(ssm, st, ctx=ctx)
    assert int(base["hits"]) >= hits_before, (
        f"the server's access log cannot shrink: {hits_before!r} -> {base['hits']!r} for {what}")
    again = _client_view(ssm, st, ctx=ctx)
    assert again["peer_vpc"]["kind"] == _DROPPED, (
        f"a second identical attempt must be dropped too, or the block was a transient: "
        f"{again['peer_vpc']!r} for {what}")
    # Both ends are alive: the client's own stack still opens a TCP connection off-box to the
    # link-local metadata service, and the server still answers its own listener.
    assert again["imds"]["kind"] == _CONNECTED, (
        f"the client's TCP stack must still work during {what}, or its timeout is about a wedged "
        f"guest rather than about the transit gateway: {again['imds']!r}")
    after = _server_view(ssm, st, ctx=ctx)
    assert st["nonce"] in after["local"], (
        f"the server stopped serving, so {what} is not evidence about the path: {after!r}")
    assert int(after["hits"]) == int(base["hits"]), (
        f"a dropped packet never reaches the far end, so the server logs no further request from "
        f"{st['client_ip']!r}; one more blocked attempt moved its log {base['hits']!r} -> "
        f"{after['hits']!r} for {what}")
    assert again["peer_vpc"]["body_error"] == "", (
        f"the guest's connect must have failed outright, not mid-body -- a truncated read would "
        f"mean something did answer: {again['peer_vpc']!r} for {what}")
    # The VPC route tables are untouched throughout: the transit gateway's own table is the only
    # thing any leg changes.
    for rtb_id, peer in ((st["rtb_a"], _VPC_B_CIDR), (st["rtb_b"], _VPC_A_CIDR)):
        route = _vpc_route(ec2, rtb_id, peer)
        assert route is not None and route.get("TransitGatewayId") == st["tgw"], (
            f"the VPC route for {peer!r} in {rtb_id!r} must be unchanged during {what}, or the "
            f"block is not the transit gateway's doing: {route!r}")
    return again, after


def _resumes(ssm, st, hits_before, what, *, ctx):
    """A positive control: the traffic comes back and the far end records it again."""
    ok = _reach(ssm, st, expect_ok=True, what=what, ctx=ctx)
    assert st["nonce"] in ok["peer_vpc"]["body"], (
        f"{what} connected but did not read the server's payload: {ok!r}")
    after = _server_view(ssm, st, ctx=ctx)
    hits = int(after["hits"])
    assert hits > hits_before, (
        f"{what}: the far end must log the request again, {hits_before!r} -> {hits!r} ({after!r})")
    return hits


def _teardown(ec2, iam, st, *, ctx) -> list:
    """Ordered teardown with waits too long for registered cleanup; returns what it left behind.

    Never raises, as it runs in a `finally`; instances go first, then the transit gateway."""
    left = []

    def _step(label, fn):
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 — reported through `left`, never propagated
            left.append(f"{label}: {exc!r}")

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i, capped=False, ctx=ctx))
    # Every route that names the transit gateway, on both sides, before the attachments go.
    for rtb_id, peer in ((st.get("rtb_a"), _VPC_B_CIDR), (st.get("rtb_b"), _VPC_A_CIDR)):
        if rtb_id:
            _step(f"vpc-route {rtb_id}", lambda r=rtb_id, p=peer: ec2.delete_route(
                RouteTableId=r, DestinationCidrBlock=p))
    # Both deletes are issued before either is waited on; one attachment takes about two minutes.
    for att in st.get("attachments", []):
        _step(f"attachment {att}", lambda a=att: ec2.delete_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId=a))
    for att in st.get("attachments", []):
        _step(f"attachment-wait {att}", lambda a=att: _poll(
            lambda: _attachment_state(ec2, a), lambda s: s in ("deleted", "gone"),
            timeout_s=600, interval_s=2, what=f"attachment {a} reporting deleted",
            capped=False, ctx=ctx))
    if st.get("tgw"):
        _step("tgw", lambda: ec2.delete_transit_gateway(TransitGatewayId=st["tgw"]))
        _step("tgw-wait", lambda: _poll(
            lambda: _tgw_state(ec2, st["tgw"]), lambda s: s in ("deleted", "gone"),
            timeout_s=600, interval_s=2, what=f"transit gateway {st['tgw']} reporting deleted",
            capped=False, ctx=ctx))
    for igw, vpc in st.get("igws", []):
        _step(f"igw-detach {igw}", lambda g=igw, v=vpc: _retry_dependency(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=g, VpcId=v), capped=False,
            ctx=ctx))
        _step(f"igw {igw}", lambda g=igw: _retry_dependency(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=g), capped=False, ctx=ctx))
    for assoc in st.get("assocs", []):
        _step(f"rtb-assoc {assoc}", lambda a=assoc: ec2.disassociate_route_table(AssociationId=a))
    for rtb_id in st.get("rtbs", []):
        _step(f"rtb {rtb_id}", lambda r=rtb_id: _retry_dependency(
            lambda: ec2.delete_route_table(RouteTableId=r), capped=False, ctx=ctx))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s), capped=False, ctx=ctx))
    for vpc in st.get("vpcs", []):
        _step(f"eni-drain {vpc}", lambda v=vpc: _poll(
            lambda: _vpc_enis(ec2, v), lambda enis: enis == [], timeout_s=420, interval_s=2,
            what=f"every ENI in {v!r} draining", capped=False, ctx=ctx))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s), capped=False, ctx=ctx))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    for vpc in st.get("vpcs", []):
        _step(f"vpc {vpc}", lambda v=vpc: _retry_dependency(
            lambda: ec2.delete_vpc(VpcId=v), capped=False, ctx=ctx))
        try:
            still = ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"]
            left.append(f"vpc {vpc} is still describable: {still!r}")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidVpcID.NotFound":
                left.append(f"vpc {vpc} describe returned "
                            f"{exc.response.get('Error', {}).get('Code')!r}")
    return left


_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidRoute.NotFound",
               "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
               "InvalidAssociationID.NotFound", "InvalidRouteTableId.NotFound",
               "InvalidTransitGatewayID.NotFound", "InvalidTransitGatewayAttachmentID.NotFound")


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
            {"Key": "sim2real", "Value": "dtgw-transit-gateway-forwards-packets"},
            {"Key": "sim2real:managed", "Value": "true"}]


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=1.0, what="", capped=True, *, ctx):
    """Poll until predicate holds; capped=False (teardown) keeps the full timeout_s."""
    if capped:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if capped and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s:.0f}s (last observed: {last!r})")
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))


def _retry_dependency(fn, timeout_s=300, interval_s=2, capped=True, *, ctx):
    if capped:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DependencyViolation" \
                    and time.monotonic() < deadline:
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
        f"this region offers {_INSTANCE_TYPE} in {usable!r}, and the check needs {want} zones")
    return usable[:want]


def _vpc(ctx, ec2, st, vpc_cidr, subnet_cidr, az, tag_name):
    """One VPC with one subnet, an internet gateway for the SSM control channel only, and a route
    table of this check's own so nothing depends on the account's default anything."""
    vpc_id = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(tag_name)}],
    )["Vpc"]["VpcId"]
    st["vpcs"].append(vpc_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(tag_name)}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
        "InvalidInternetGatewayID.NotFound"))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    st["igws"].append((igw_id, vpc_id))
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
        "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached"))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(tag_name)}],
    )["RouteTable"]["RouteTableId"]
    st["rtbs"].append(rtb_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_route_table(RouteTableId=rtb_id), "InvalidRouteTableID.NotFound"))
    assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
    st["assocs"].append(assoc)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.disassociate_route_table(AssociationId=assoc), "InvalidAssociationID.NotFound"))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw_id)
    return vpc_id, subnet_id, rtb_id


def _create_sg(ctx, ec2, st, vpc_id, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_security_group(GroupId=sg), "InvalidGroup.NotFound"))
    return sg


def _create_tgw(ctx, ec2, st, name):
    tgw = ec2.create_transit_gateway(
        Description=name,
        Options={"DefaultRouteTableAssociation": "enable",
                 "DefaultRouteTablePropagation": "disable",
                 "AutoAcceptSharedAttachments": "disable",
                 "DnsSupport": "enable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": _tags_for(name)}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw_if_live(ec2, tgw))
    return tgw


def _attach(ctx, ec2, st, vpc_id, subnet_id, tag_name):
    att = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=st["tgw"], VpcId=vpc_id, SubnetIds=[subnet_id],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment",
                            "Tags": _tags_for(tag_name)}],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    st["attachments"].append(att)
    ctx.on_cleanup(lambda: _delete_attachment_if_live(ec2, att))
    return att


def _attachment_state(ec2, att):
    try:
        found = ec2.describe_transit_gateway_vpc_attachments(
            TransitGatewayAttachmentIds=[att])["TransitGatewayVpcAttachments"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == \
                "InvalidTransitGatewayAttachmentID.NotFound":
            return "gone"
        raise
    return found[0]["State"] if found else "gone"


def _tgw_state(ec2, tgw):
    try:
        found = ec2.describe_transit_gateways(TransitGatewayIds=[tgw])["TransitGateways"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidTransitGatewayID.NotFound":
            return "gone"
        raise
    return found[0]["State"] if found else "gone"


def _delete_attachment_if_live(ec2, att):
    """A backup delete: an attachment the in-band teardown already deleted needs no second delete;
    anything still live is deleted for real."""
    if _attachment_state(ec2, att) in ("deleting", "deleted", "gone"):
        return
    ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=att)


def _delete_tgw_if_live(ec2, tgw):
    """A backup delete: a transit gateway the in-band teardown already deleted needs no second
    delete; anything still live is deleted for real."""
    if _tgw_state(ec2, tgw) in ("deleting", "deleted", "gone"):
        return
    ec2.delete_transit_gateway(TransitGatewayId=tgw)


def _route_table_associations(ec2, rtb):
    """Paginated by hand: GetTransitGatewayRouteTableAssociations has no paginator."""
    out, token = [], None
    while True:
        kwargs = {"TransitGatewayRouteTableId": rtb}
        if token:
            kwargs["NextToken"] = token
        page = ec2.get_transit_gateway_route_table_associations(**kwargs)
        out.extend(page.get("Associations", []))
        token = page.get("NextToken")
        if not token:
            return out


def _put_route(ec2, rtb, cidr, attachment):
    return _call_with_retry(lambda: ec2.create_transit_gateway_route(
        TransitGatewayRouteTableId=rtb, DestinationCidrBlock=cidr,
        TransitGatewayAttachmentId=attachment))["Route"]


def _replace_route(ec2, rtb, cidr, attachment=None, blackhole=False):
    kwargs = {"TransitGatewayRouteTableId": rtb, "DestinationCidrBlock": cidr}
    if blackhole:
        kwargs["Blackhole"] = True
    else:
        kwargs["TransitGatewayAttachmentId"] = attachment
    return _call_with_retry(
        lambda: ec2.replace_transit_gateway_route(**kwargs))["Route"]


def _tgw_route(ec2, rtb, cidr):
    """The route for exactly `cidr`, or None, via SearchTransitGatewayRoutes.

    Eventually consistent: a just-created route can take seconds to appear, hence `_await_route`."""
    routes = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=rtb,
        Filters=[{"Name": "route-search.subnet-of-match", "Values": ["0.0.0.0/0"]}])["Routes"]
    exact = [r for r in routes if r.get("DestinationCidrBlock") == cidr]
    assert len(exact) <= 1, f"more than one route for {cidr!r} in {rtb!r}: {exact!r}"
    return exact[0] if exact else None


def _await_route(ec2, rtb, cidr, predicate, what, *, ctx):
    return _poll(lambda: _tgw_route(ec2, rtb, cidr), predicate,
                 timeout_s=240, interval_s=1, what=what, ctx=ctx)


def _vpc_route(ec2, rtb_id, cidr):
    table = ec2.describe_route_tables(RouteTableIds=[rtb_id])["RouteTables"][0]
    for route in table["Routes"]:
        if route.get("DestinationCidrBlock") == cidr:
            return route
    return None


def _vpc_enis(ec2, vpc_id):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]]


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real dtgw transit gateway data plane",
                    Tags=[{"Key": "sim2real", "Value": "dtgw-transit-gateway-forwards-packets"}])
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY),
        "NoSuchEntity"))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "dtgw-transit-gateway-forwards-packets"}])
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name), "NoSuchEntity"))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name),
        "NoSuchEntity"))
    # IAM exposes no "this role is usable" condition to poll. `_launch`'s bounded retry on
    # InvalidParameterValue is what makes this correct; no sleep stands in for it.


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(25):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name)
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 24:
                raise
            time.sleep(2)
    iam.delete_instance_profile(InstanceProfileName=profile_name)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    for attempt in range(25):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DeleteConflict" and attempt < 24:
                time.sleep(2)
                continue
            raise


def _launch(ctx, ec2, st, ami, subnet_id, sg_id, tag_name, user_data=None, private_ip=None):
    # A public address for the SSM control channel, a path no leg ever touches.
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
                           retries=60, delay=2.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[iid]))
    return iid


def _wait_terminated(ec2, instance_id, timeout_s=600, capped=True, *, ctx):
    if capped:
        timeout_s = _budget_s(ctx, timeout_s)
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


def _run_phase(ssm, instance_id, script, timeout_s=300, *, ctx):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real dtgw leg"), codes=_THROTTLE + ("InvalidInstanceId",),
        retries=60, delay=2.0)
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=1.0,
                 what=f"invocation {command_id} reaching a terminal status", ctx=ctx)


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


# Run inside the guest, as the runner cannot reach a private address; `kind` is the guest
# kernel's classification: `timeout` means the SYN was dropped, `refused` means an RST came back.
_CLIENT_PROBE = """set -uo pipefail
python3 - <<'PYEOF'
import json, socket


def probe(host, port, timeout, request=None):
    # `kind` classifies THE CONNECT ONLY, so that a read that stalls after the handshake can never
    # be mistaken for a dropped SYN: the two would both raise socket.timeout, and only one of them
    # is evidence that the transit gateway discarded the packet.
    out = {"ok": False, "kind": "", "peer": "", "body": "", "body_error": ""}
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError as exc:
        out["kind"] = "refused:%s" % (exc.errno,)
        return out
    except socket.timeout:
        out["kind"] = "timeout"
        return out
    except OSError as exc:
        out["kind"] = "oserror:%s:%s" % (type(exc).__name__, exc.errno)
        return out
    out["ok"] = True
    out["kind"] = "connected"
    out["peer"] = sock.getsockname()[0]
    try:
        if request is not None:
            sock.settimeout(timeout)
            sock.sendall(request)
            buf = b""
            while len(buf) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            out["body"] = buf.decode("utf-8", "replace")[-400:]
    except OSError as exc:
        out["body_error"] = "%s:%s" % (type(exc).__name__, exc.errno)
    finally:
        sock.close()
    return out


REQUEST = b"GET /nonce HTTP/1.0\\r\\nHost: sim2real\\r\\nConnection: close\\r\\n\\r\\n"
print(json.dumps({"peer_vpc": probe("__SERVER_IP__", __PORT__, 2.0, REQUEST),
                  "imds": probe("169.254.169.254", 80, 3.0)}))
PYEOF
"""

# `http.server` logs the source address of each completed request, so a line starting with the
# client's private address proves the packet arrived at the far end.
_SERVER_PROBE = """set -uo pipefail
python3 - <<'PYEOF'
import json, socket

out = {"local": "", "hits": 0, "last": []}
sock = None
try:
    sock = socket.create_connection(("127.0.0.1", __PORT__), timeout=5.0)
    sock.settimeout(5.0)
    sock.sendall(b"GET /nonce HTTP/1.0\\r\\nHost: sim2real\\r\\nConnection: close\\r\\n\\r\\n")
    buf = b""
    while len(buf) < 8192:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    out["local"] = buf.decode("utf-8", "replace")[-400:]
except OSError as exc:
    out["local"] = "ERR:%s" % (type(exc).__name__,)
finally:
    if sock is not None:
        sock.close()
try:
    with open("/tmp/httpd.log") as fh:
        log = fh.read()
except OSError:
    log = ""
peers = [ln for ln in log.splitlines() if ln.startswith("__CLIENT_IP__ ")]
out["hits"] = len(peers)
out["last"] = peers[-2:] or [""]
print(json.dumps(out))
PYEOF
"""


def _client_view(ssm, st, *, ctx):
    script = _CLIENT_PROBE.replace("__SERVER_IP__", _SERVER_IP).replace("__PORT__", str(_PORT))
    return _json_line(_run_phase(ssm, st["client"], script, ctx=ctx))


def _server_view(ssm, st, *, ctx):
    script = _SERVER_PROBE.replace("__PORT__", str(_PORT)).replace(
        "__CLIENT_IP__", st["client_ip"])
    return _json_line(_run_phase(ssm, st["server"], script, ctx=ctx))


def _reach(ssm, st, expect_ok, what, *, ctx):
    """Drive one leg from inside the client, polling until the expected outcome or a FAIL that names
    what the guest last saw."""
    return _poll(lambda: _client_view(ssm, st, ctx=ctx),
                 lambda r: r["peer_vpc"]["ok"] is expect_ok,
                 timeout_s=300, interval_s=1.0, what=what, ctx=ctx)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
