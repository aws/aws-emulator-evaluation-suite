"""dpeer-route-is-blackhole-until-the-peering-is-accepted."""
from __future__ import annotations

import base64
import json
import sys
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dpeer-route-is-blackhole-until-the-peering-is-accepted"
GROUP = "data-plane"
SERVICES = ["ec2"]

_A_VPC_CIDR = "10.63.0.0/16"
_B_VPC_CIDR = "10.64.0.0/16"
_A_SUB_CIDR = "10.63.1.0/24"
_B_SUB_CIDR = "10.64.1.0/24"
_A_IP = "10.63.1.10"
_B_IP = "10.64.1.10"
_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
# curl(1): 28 is "Operation timeout", 7 is "Failed to connect". A packet the VPC router DROPS
# gives 28; a host that answers with a reset gives 7.
_CURL_TIMEOUT = 28


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A route to a pending-acceptance peering is created as blackhole and drops TCP both ways; the
    same routes go active and carry traffic once accepted, and revert to blackhole on deletion.
    """
    _RUN.ctx = ctx
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"sides": {}, "instances": [], "igws": [], "sgs": [], "subnets": [], "vpcs": [],
                "pcx": None}
    # Teardown is in-band: waiting for instances to terminate before detaching the internet
    # gateways outlasts the 60 s on_cleanup budget, which would leak the VPCs.
    try:
        _build(ctx, ec2, ssm, iam, st)
        _legs(ctx, ec2, ssm, st)
    finally:
        _teardown(ec2, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-dpeer-pend-")
    st["name"] = name

    # Every decidable precondition ahead of the first create: an unusable region must cost nothing.
    zone = _usable_zones(ec2, want=1)[0]
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    a = _side(ctx, ec2, st, "a", name + "-a", _A_VPC_CIDR, _A_SUB_CIDR, zone, _B_VPC_CIDR)
    b = _side(ctx, ec2, st, "b", name + "-b", _B_VPC_CIDR, _B_SUB_CIDR, zone, _A_VPC_CIDR)

    a["nonce"] = name + "-nonce-a"
    b["nonce"] = name + "-nonce-b"
    a["instance"] = _launch(ctx, ec2, st, ami, a, name + "-a", a["nonce"])
    b["instance"] = _launch(ctx, ec2, st, ami, b, name + "-b", b["nonce"])

    for key in ("a", "b"):
        side = st["sides"][key]
        info = _poll(lambda s=side: _agent_view(ssm, s["instance"]),
                     lambda i: i is not None and i.get("PingStatus") == "Online",
                     timeout_s=600, interval_s=2.0,
                     what=f"the SSM agent on side {key} ({side['instance']}) coming Online over "
                          f"its own internet gateway {side['igw']}")
        assert info["PingStatus"] == "Online", f"side {key}'s agent view was {info!r}"

    # RunInstances is eventually consistent: DescribeInstances can 404 an id it has just minted.
    ids = [st["sides"]["a"]["instance"], st["sides"]["b"]["instance"]]
    described = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=ids),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=30, delay=2.0)["Reservations"]
    by_id = {i["InstanceId"]: i for r in described for i in r["Instances"]}
    for key, want_ip in (("a", _A_IP), ("b", _B_IP)):
        got = by_id[st["sides"][key]["instance"]]["PrivateIpAddress"]
        assert got == want_ip, (
            f"side {key} did not take the fixed address the legs target: {got!r} != {want_ip!r}")

    # The barrier: nothing below is interpretable unless both hosts serve their own nonce.
    for key in ("a", "b"):
        side = st["sides"][key]
        local = _poll(lambda s=side: _server_view(ssm, st, s),
                      lambda v: v["local"] == side["nonce"], timeout_s=420, interval_s=2.0,
                      what=f"side {key}'s own listener answering on 127.0.0.1:{_PORT} with "
                           f"{side['nonce']!r}")
        assert local["local"] == side["nonce"], (
            f"side {key} must answer its own listener before any leg runs; it returned "
            f"{local['local']!r}, expected {side['nonce']!r}")


# ===== the three legs =======================================================
def _legs(ctx, ec2, ssm, st) -> None:
    a, b = st["sides"]["a"], st["sides"]["b"]

    pcx = ec2.create_vpc_peering_connection(
        VpcId=a["vpc"], PeerVpcId=b["vpc"],
        TagSpecifications=[{"ResourceType": "vpc-peering-connection",
                            "Tags": _tags_for(st["name"])}],
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    st["pcx"] = pcx
    ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_pcx_if_live(ec2, pcx),
                                        "InvalidVpcPeeringConnectionID.NotFound"))
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "pending-acceptance", timeout_s=180,
          interval_s=2.0, what=f"peering {pcx} reaching pending-acceptance")

    # --- L1: routes on both sides, connection NOT accepted -> blackhole -------
    # CreateRoute against a pending-acceptance peering is accepted by real AWS, which is what makes
    # this leg possible at all; a refusal here would be a fidelity gap, not an expected outcome.
    _add_peer_route(ec2, a["rtb"], _B_VPC_CIDR, pcx)
    _add_peer_route(ec2, b["rtb"], _A_VPC_CIDR, pcx)
    assert _pcx_status(ec2, pcx) == "pending-acceptance", (
        f"the connection must still be unaccepted for L1 to mean anything: "
        f"{_pcx_status(ec2, pcx)!r}")
    _assert_route_state(ec2, a["rtb"], _B_VPC_CIDR, pcx, "blackhole", "L1 side a")
    _assert_route_state(ec2, b["rtb"], _A_VPC_CIDR, pcx, "blackhole", "L1 side b")
    _both_blocked(ssm, st, "L1 with the peering still pending-acceptance and both routes blackhole")

    # --- L2: accept, touching nothing else -> the same routes go active -------
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "active", timeout_s=300, interval_s=2.0,
          what=f"peering {pcx} reaching active after acceptance")
    _poll(lambda: (_route(ec2, a["rtb"], _B_VPC_CIDR), _route(ec2, b["rtb"], _A_VPC_CIDR)),
          lambda pair: all(r is not None and r.get("State") == "active" for r in pair),
          timeout_s=300, interval_s=2.0,
          what="both peer routes turning active once the connection was accepted, with no route "
               "rewritten")
    _assert_route_state(ec2, a["rtb"], _B_VPC_CIDR, pcx, "active", "L2 side a")
    _assert_route_state(ec2, b["rtb"], _A_VPC_CIDR, pcx, "active", "L2 side b")
    _both_reachable(ssm, st, "L2 with the identical routes after the peering was accepted")

    # --- L3: delete the connection, touching no route -> blackhole again ------
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "deleted", timeout_s=300, interval_s=2.0,
          what=f"peering {pcx} reaching deleted")
    _poll(lambda: (_route(ec2, a["rtb"], _B_VPC_CIDR), _route(ec2, b["rtb"], _A_VPC_CIDR)),
          lambda pair: all(r is not None and r.get("State") == "blackhole" for r in pair),
          timeout_s=300, interval_s=2.0,
          what="both peer routes reverting to blackhole once the connection was deleted, with no "
               "route rewritten")
    _assert_route_state(ec2, a["rtb"], _B_VPC_CIDR, pcx, "blackhole", "L3 side a")
    _assert_route_state(ec2, b["rtb"], _A_VPC_CIDR, pcx, "blackhole", "L3 side b")
    _both_blocked(ssm, st, "L3 with the identical routes after the peering was deleted")


def _both_reachable(ssm, st, what) -> None:
    a, b = st["sides"]["a"], st["sides"]["b"]
    before_a = _server_view(ssm, st, a)
    before_b = _server_view(ssm, st, b)
    a_to_b = _reach(ssm, st, a, b, expect_ok=True, what=f"{what}: a -> b")
    b_to_a = _reach(ssm, st, b, a, expect_ok=True, what=f"{what}: b -> a")
    assert a_to_b["rc"] == 0 and a_to_b["code"] == "200", f"{what}: a could not reach b: {a_to_b!r}"
    assert a_to_b["body"] == b["nonce"], (
        f"{what}: a reached something that is not b's own payload -- expected {b['nonce']!r}, got "
        f"{a_to_b!r}")
    assert b_to_a["rc"] == 0 and b_to_a["code"] == "200", f"{what}: b could not reach a: {b_to_a!r}"
    assert b_to_a["body"] == a["nonce"], (
        f"{what}: b reached something that is not a's own payload -- expected {a['nonce']!r}, got "
        f"{b_to_a!r}")
    after_a = _server_view(ssm, st, a)
    after_b = _server_view(ssm, st, b)
    assert int(after_b["hits"]) > int(before_b["hits"]), (
        f"{what}: b's own access log must record the request from a ({_A_IP}): "
        f"{before_b['hits']!r} -> {after_b['hits']!r}")
    assert int(after_a["hits"]) > int(before_a["hits"]), (
        f"{what}: a's own access log must record the request from b ({_B_IP}): "
        f"{before_a['hits']!r} -> {after_a['hits']!r}")


def _both_blocked(ssm, st, what) -> None:
    """Converge to blocked in both directions, then prove ONE more identical attempt each way
    leaves the peer's own access log untouched."""
    a, b = st["sides"]["a"], st["sides"]["b"]
    first_ab = _reach(ssm, st, a, b, expect_ok=False, what=f"{what}: a -> b")
    first_ba = _reach(ssm, st, b, a, expect_ok=False, what=f"{what}: b -> a")
    assert first_ab["rc"] == _CURL_TIMEOUT, (
        f"{what}: a DROPPED packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7): a -> b was {first_ab!r}")
    assert first_ba["rc"] == _CURL_TIMEOUT, (
        f"{what}: a DROPPED packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7): b -> a was {first_ba!r}")

    # Attempts made before the state change took effect do cross and get logged, so the baseline
    # is taken after convergence.
    base_a, base_b = _server_view(ssm, st, a), _server_view(ssm, st, b)
    again_ab = _json_line(_run_phase(ssm, a["instance"], _client_script(b["ip"])))
    again_ba = _json_line(_run_phase(ssm, b["instance"], _client_script(a["ip"])))
    for label, got in (("a -> b", again_ab), ("b -> a", again_ba)):
        assert got["rc"] == _CURL_TIMEOUT, (
            f"{what}: a second identical attempt must be blocked too, or the block was a "
            f"transient: {label} was {got!r}")
        assert got["body"] == "", f"{what}: {label} returned a body, so something answered: {got!r}"
    after_a, after_b = _server_view(ssm, st, a), _server_view(ssm, st, b)

    # The peers are alive: each still answers its own listener, so the timeouts are about the path.
    assert after_a["local"] == a["nonce"], (
        f"{what}: a stopped serving, so the blocked legs are not evidence about the peering: "
        f"{after_a!r}")
    assert after_b["local"] == b["nonce"], (
        f"{what}: b stopped serving, so the blocked legs are not evidence about the peering: "
        f"{after_b!r}")
    # The effect is ABSENT: a blackhole route drops the packet, so the connection never establishes
    # and neither peer logs a completed request.
    assert int(after_b["hits"]) == int(base_b["hits"]), (
        f"{what}: a blackhole route drops the packet, so b logs no completed request; one further "
        f"blocked attempt moved b's log {base_b['hits']!r} -> {after_b['hits']!r}")
    assert int(after_a["hits"]) == int(base_a["hits"]), (
        f"{what}: one further blocked attempt moved a's log {base_a['hits']!r} -> "
        f"{after_a['hits']!r}")


# ===== in-band teardown =====================================================
def _teardown(ec2, iam, st) -> None:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises what it could not remove, carrying any failure in flight."""
    left: list = []
    steps: list = []
    found = sys.exc_info()[1]  # the body's failure in flight, if any

    def _step(label, fn):
        steps.append((label, fn))

    # Every terminate is ISSUED before any wait, so two instances cost the max and not the sum.
    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i))
    # Network resources before IAM. L3 already deleted the peering, so this is the path where the
    # check failed before reaching it.
    if st.get("pcx"):
        _step("pcx", lambda: _delete_pcx_if_live(ec2, st["pcx"]))
    for vpc_id, igw in st.get("igws", []):
        _step(f"igw-detach {igw}", lambda v=vpc_id, g=igw: _retry_dependency(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=g, VpcId=v)))
        _step(f"igw {igw}", lambda g=igw: _retry_dependency(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=g)))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    for vpc_id in st.get("vpcs", []):
        _step(f"vpc {vpc_id}", lambda v=vpc_id: _retry_dependency(
            lambda: ec2.delete_vpc(VpcId=v)))
        _step(f"vpc-gone {vpc_id}", lambda v=vpc_id: _assert_vpc_gone(ec2, v))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 - collected, raised after the loop
            left.append(f"{label}: {exc!r}")
    if left:
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")


def _delete_pcx_if_live(ec2, pcx):
    """A connection already in `deleted` (L3's own act) refuses a second delete with
    InvalidStateTransition, which is not a leak; anything else is deleted for real."""
    if _pcx_status(ec2, pcx) in ("deleted", "deleting", "rejected", "failed", "expired"):
        return
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)


def _assert_vpc_gone(ec2, vpc_id):
    still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    raise AssertionError(f"vpc {vpc_id} is still describable after delete: {still!r}")


def _unless_gone(fn, *codes):
    """A backup cleanup the in-band teardown may already have done: only *codes* (the resource's
    own not-found) count as done; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
               "InvalidVpcPeeringConnectionID.NotFound", "InvalidRoute.NotFound")


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "dpeer-pending-blackhole"},
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


#: The running check's context, per thread, so every poll ends before the run's budget does.
_RUN = threading.local()


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=2.0, what=""):
    ctx = getattr(_RUN, "ctx", None)
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
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _retry_dependency(fn, timeout_s=300, interval_s=2.0):
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


def _side(ctx, ec2, st, key, tag_name, vpc_cidr, sub_cidr, zone, peer_cidr) -> dict:
    """One whole side of the peering: a VPC with its own internet gateway, so the SSM control
    channel that reports every verdict never depends on the peering being up."""
    vpc_id = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(tag_name)}],
    )["Vpc"]["VpcId"]
    st["vpcs"].append(vpc_id)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                        "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id],
                                         WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(tag_name)}],
    )["InternetGateway"]["InternetGatewayId"]
    st["igws"].append((vpc_id, igw))
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw),
        "InvalidInternetGatewayID.NotFound"))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id),
        "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached"))

    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=sub_cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet),
                                        "InvalidSubnetID.NotFound"))

    # The VPC's own main route table: it is created and destroyed with the VPC this check built,
    # so the legs can mutate it without a route table of their own to associate and disassociate.
    rtb = _main_route_table(ec2, vpc_id)
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)

    sg = ec2.create_security_group(
        GroupName=tag_name, Description="sim2real dpeer pending-blackhole side", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(tag_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_security_group(GroupId=sg),
                                        "InvalidGroup.NotFound"))
    # Only the peer's CIDR may reach the listener, so a leg can never be satisfied by anything
    # other than a packet that crossed the peering.
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": peer_cidr}]}])

    side = {"vpc": vpc_id, "igw": igw, "subnet": subnet, "rtb": rtb, "sg": sg,
            "ip": _A_IP if key == "a" else _B_IP, "cidr": vpc_cidr, "key": key}
    st["sides"][key] = side
    return side


def _main_route_table(ec2, vpc_id):
    rtbs = []
    paginator = ec2.get_paginator("describe_route_tables")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                                            {"Name": "association.main", "Values": ["true"]}]):
        rtbs.extend(page["RouteTables"])
    assert len(rtbs) == 1, (
        f"expected exactly one main route table in the VPC this check just created {vpc_id!r}; "
        f"found {[r['RouteTableId'] for r in rtbs]!r}")
    return rtbs[0]["RouteTableId"]


def _add_peer_route(ec2, rtb, dest_cidr, pcx):
    _call_with_retry(lambda: ec2.create_route(
        RouteTableId=rtb, DestinationCidrBlock=dest_cidr, VpcPeeringConnectionId=pcx))


def _routes(ec2, rtb):
    tables = []
    paginator = ec2.get_paginator("describe_route_tables")
    for page in paginator.paginate(RouteTableIds=[rtb]):
        tables.extend(page["RouteTables"])
    assert len(tables) == 1, f"expected exactly one route table for {rtb!r}; got {tables!r}"
    return tables[0]["Routes"]


def _route(ec2, rtb, dest_cidr):
    matches = [r for r in _routes(ec2, rtb) if r.get("DestinationCidrBlock") == dest_cidr]
    return matches[0] if len(matches) == 1 else None


def _assert_route_state(ec2, rtb, dest_cidr, pcx, want_state, label):
    routes = _routes(ec2, rtb)
    matches = [r for r in routes if r.get("DestinationCidrBlock") == dest_cidr]
    assert len(matches) == 1, (
        f"{label}: expected exactly one route to {dest_cidr!r} in {rtb!r}; the table holds "
        f"{routes!r}")
    route = matches[0]
    assert route.get("VpcPeeringConnectionId") == pcx, (
        f"{label}: the route to {dest_cidr!r} must name the peering {pcx!r}: {route!r}")
    assert route.get("Origin") == "CreateRoute", (
        f"{label}: the route must be the one this check created: {route!r}")
    assert route.get("State") == want_state, (
        f"{label}: the route to {dest_cidr!r} must be {want_state!r}: {route!r}")
    return route


def _pcx_status(ec2, pcx):
    conns = ec2.describe_vpc_peering_connections(
        VpcPeeringConnectionIds=[pcx])["VpcPeeringConnections"]
    assert len(conns) == 1, f"expected exactly one peering connection for {pcx!r}; got {conns!r}"
    return conns[0]["Status"]["Code"]


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real dpeer pending-blackhole control channel",
                    Tags=[{"Key": "sim2real", "Value": "dpeer-pending-blackhole"}])
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_role(RoleName=role_name),
                                        "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn=_SSM_CORE_POLICY), "NoSuchEntity"))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "dpeer-pending-blackhole"}])
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name), "NoSuchEntity"))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name), "NoSuchEntity"))
    # IAM exposes no "this role is usable" condition to poll. `_launch`'s own bounded retry on
    # InvalidParameterValue is what actually makes this correct; no sleep is needed here.


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


def _user_data(nonce):
    return (
        "#!/bin/bash\n"
        "mkdir -p /tmp/srv\n"
        f"printf '%s' '{nonce}' > /tmp/srv/nonce\n"
        "cd /tmp/srv\n"
        f"nohup python3 -m http.server {_PORT} --bind 0.0.0.0 > /tmp/httpd.log 2>&1 &\n"
    )


def _launch(ctx, ec2, st, ami, side, tag_name, nonce):
    nic = {"DeviceIndex": 0, "SubnetId": side["subnet"], "Groups": [side["sg"]],
           "AssociatePublicIpAddress": True, "PrivateIpAddress": side["ip"]}
    iid = _call_with_retry(lambda: ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        NetworkInterfaces=[nic], IamInstanceProfile={"Name": st["profile"]},
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        UserData=base64.b64encode(_user_data(nonce).encode()).decode(),
        # Tagged in the SAME call, so the instance is never untagged.
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume")],
    ), codes=_THROTTLE + ("InvalidParameterValue",), retries=75,
        delay=2.0)["Instances"][0]["InstanceId"]
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


def _run_phase(ssm, instance_id, script, timeout_s=300):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real dpeer leg"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=2.0,
                 what=f"invocation {command_id} reaching a terminal status")


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


def _client_script(target_ip):
    # /tmp/body is removed first: curl only truncates its output file once bytes arrive, so a leg
    # that times out would otherwise report the PREVIOUS leg's body and read as reachable.
    return f"""set -uo pipefail
rm -f /tmp/body
CODE=$(curl -s --connect-timeout 2 -m 8 -o /tmp/body -w '%{{http_code}}' http://{target_ip}:{_PORT}/nonce)
RC=$?
export CODE RC
python3 - <<'JEOF'
import json, os
d = {{"rc": int(os.environ.get("RC", "-1")), "code": os.environ.get("CODE", "")}}
try:
    with open("/tmp/body") as fh:
        d["body"] = fh.read()[:200]
except OSError:
    d["body"] = ""
print(json.dumps(d))
JEOF
"""


def _server_script(peer_ip):
    return f"""set -uo pipefail
LOCAL=$(curl -s -m 5 http://127.0.0.1:{_PORT}/nonce || true)
HITS=$(grep -c '{peer_ip}' /tmp/httpd.log || true)
export LOCAL HITS
python3 - <<'JEOF'
import json, os
print(json.dumps({{"local": os.environ.get("LOCAL", ""),
                  "hits": os.environ.get("HITS", "") or "0"}}))
JEOF
"""


def _server_view(ssm, st, side):
    peer = st["sides"]["b" if side["key"] == "a" else "a"]
    return _json_line(_run_phase(ssm, side["instance"], _server_script(peer["ip"])))


def _reach(ssm, st, src, dst, expect_ok, what):
    """Drive one leg from `src` and poll until the expected outcome, so a peering state change that
    has not converged yet is a retry and a change that never converges is a FAIL naming what was
    last seen."""
    return _poll(lambda: _json_line(_run_phase(ssm, src["instance"], _client_script(dst["ip"]))),
                 lambda r: (r["rc"] == 0) is expect_ok,
                 timeout_s=300, interval_s=2.0, what=what)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
