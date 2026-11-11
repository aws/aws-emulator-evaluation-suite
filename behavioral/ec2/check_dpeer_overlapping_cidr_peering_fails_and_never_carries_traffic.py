"""dpeer-overlapping-cidr-peering-fails-and-never-carries-traffic."""
from __future__ import annotations

import base64
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dpeer-overlapping-cidr-peering-fails-and-never-carries-traffic"
GROUP = "data-plane"
SERVICES = ["ec2"]

# A and B deliberately share a CIDR; C is disjoint from both and is the positive control.
_A_VPC_CIDR = "10.65.0.0/16"
_B_VPC_CIDR = "10.65.0.0/16"
_PCX_FAILED_MESSAGE = (
    "Failed due to incorrect VPC-ID, Account ID, overlapping CIDR range, or VPC Encryption Control posture"
)
_C_VPC_CIDR = "10.66.0.0/16"
_A_SUB_CIDR = "10.65.1.0/24"
_C_SUB_CIDR = "10.66.1.0/24"
_A_IP = "10.65.1.10"
_C_IP = "10.66.1.10"
# Inside the overlapping space and allocated to nobody: the address a route to B would have had to
# carry. It is in A's OWN CIDR, which is precisely why no peering could ever deliver it.
_OVERLAP_IP = "10.65.9.10"
_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
# curl(1): 28 is "Operation timeout", 7 is "Failed to connect". A packet the VPC router DROPS gives
# 28; a host answering with a reset gives 7.
_CURL_TIMEOUT = 28
_PCX_DEAD = ("failed", "deleted", "deleting", "rejected", "expired")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Peering two VPCs with overlapping CIDRs is accepted, then fails (failed admits no
    transition), a route to the peer CIDR is refused, and traffic into the overlap times out; a
    disjoint peering carries traffic both ways until deleted, after which routes blackhole.

    Reference: https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"sides": {}, "instances": [], "igws": [], "sgs": [], "subnets": [], "vpcs": [],
                "pcx_ac": None}
    try:
        _build(ctx, ec2, ssm, iam, st)
        _leg1_overlapping_peering_fails(ctx, ec2, st)
        _leg2_nothing_moves_into_the_overlap(ssm, st)
        _leg3_and_4_disjoint_peer_carries_traffic(ctx, ec2, ssm, st)
    finally:
        _teardown(ec2, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-dpeer-ovl-")
    st["name"] = name

    zone = _usable_zones(ec2, want=1)[0]
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    # A and C are full sides; B exists only to collide with A's address space, so it needs no
    # subnet, no instance and no route table entry of its own.
    a = _side(ctx, ec2, st, "a", name + "-a", _A_VPC_CIDR, _A_SUB_CIDR, zone, _C_VPC_CIDR)
    c = _side(ctx, ec2, st, "c", name + "-c", _C_VPC_CIDR, _C_SUB_CIDR, zone, _A_VPC_CIDR)
    st["vpc_b"] = _bare_vpc(ctx, ec2, st, name + "-b", _B_VPC_CIDR)

    assert st["vpc_b"] != a["vpc"], "B must be a second, distinct VPC that merely shares A's CIDR"
    b_cidr = ec2.describe_vpcs(VpcIds=[st["vpc_b"]])["Vpcs"][0]["CidrBlock"]
    assert b_cidr == _A_VPC_CIDR, (
        f"the premise of L1 is that B's CIDR collides with A's; B came up as {b_cidr!r}")

    a["nonce"] = name + "-nonce-a"
    c["nonce"] = name + "-nonce-c"
    a["instance"] = _launch(ctx, ec2, st, ami, a, name + "-a", a["nonce"])
    c["instance"] = _launch(ctx, ec2, st, ami, c, name + "-c", c["nonce"])

    for key in ("a", "c"):
        side = st["sides"][key]
        info = _poll(lambda s=side: _agent_view(ssm, s["instance"]),
                     lambda i: i is not None and i.get("PingStatus") == "Online",
                     timeout_s=600, interval_s=10,
                     what=f"the SSM agent on side {key} ({side['instance']}) coming Online over "
                          f"its own internet gateway {side['igw']}")
        assert info["PingStatus"] == "Online", f"side {key}'s agent view was {info!r}"

    ids = [st["sides"]["a"]["instance"], st["sides"]["c"]["instance"]]
    described = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=ids),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=12, delay=5.0)["Reservations"]
    by_id = {i["InstanceId"]: i for r in described for i in r["Instances"]}
    for key, want_ip in (("a", _A_IP), ("c", _C_IP)):
        got = by_id[st["sides"][key]["instance"]]["PrivateIpAddress"]
        assert got == want_ip, (
            f"side {key} did not take the fixed address the legs target: {got!r} != {want_ip!r}")

    for key in ("a", "c"):
        side = st["sides"][key]
        local = _poll(lambda s=side: _server_view(ssm, st, s),
                      lambda v: v["local"] == side["nonce"], timeout_s=420, interval_s=10,
                      what=f"side {key}'s own listener answering on 127.0.0.1:{_PORT} with "
                           f"{side['nonce']!r}")
        assert local["local"] == side["nonce"], (
            f"side {key} must answer its own listener before any leg runs; it returned "
            f"{local['local']!r}, expected {side['nonce']!r}")


# ===== L1: the overlapping peering ==========================================
def _leg1_overlapping_peering_fails(ctx, ec2, st) -> None:
    a = st["sides"]["a"]

    created = ec2.create_vpc_peering_connection(
        VpcId=a["vpc"], PeerVpcId=st["vpc_b"],
        TagSpecifications=[{"ResourceType": "vpc-peering-connection",
                            "Tags": _tags_for(st["name"] + "-overlap")}],
    )["VpcPeeringConnection"]
    pcx = created["VpcPeeringConnectionId"]
    st["pcx_ab"] = pcx
    ctx.on_cleanup(lambda: _delete_pcx_if_live(ec2, pcx))

    # Overlapping CIDRs are NOT a synchronous refusal: a connection really is created.
    assert pcx.startswith("pcx-"), (
        f"an overlapping-CIDR request must still mint a connection id: {created!r}")
    assert created["Status"]["Code"] == "initiating-request", (
        f"the request must be accepted as initiating-request, not refused and not pre-failed: "
        f"{created['Status']!r}")

    status = _poll(lambda: _pcx_status_full(ec2, pcx), lambda s: s["Code"] != "initiating-request",
                   timeout_s=420, interval_s=5.0,
                   what=f"overlapping-CIDR peering {pcx} leaving initiating-request")
    assert status["Code"] == "failed", (
        f"an overlapping-CIDR peering must end in failed, never pending-acceptance or active: "
        f"{status!r}")
    assert status.get("Message") == _PCX_FAILED_MESSAGE, (
        f"the failure must name the overlapping CIDR range as a reason: {status!r}")

    # A failed connection is inert in every direction: no transition out of it exists.
    for label, target, call in (
        ("accept", "provisioning", lambda: ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)),
        ("reject", "rejected", lambda: ec2.reject_vpc_peering_connection(VpcPeeringConnectionId=pcx)),
        ("delete", "deleting", lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)),
    ):
        code, message = _error(call)
        assert code == "InvalidStateTransition", (
            f"{label} on a failed peering must raise exactly InvalidStateTransition; got {code!r}")
        assert message == f"Invalid state transition for {pcx}, attempted to transition from failed to {target}", (
            f"{label} on a failed peering: unexpected InvalidStateTransition message {message!r}")

    # Scoped to the VPC this check created, never an account-wide listing.
    live = ec2.describe_vpc_peering_connections(Filters=[
        {"Name": "requester-vpc-info.vpc-id", "Values": [a["vpc"]]},
        {"Name": "status-code",
         "Values": ["initiating-request", "pending-acceptance", "provisioning", "active"]},
    ])["VpcPeeringConnections"]
    assert live == [], (
        f"no live peering may be attributable to A after the overlapping request failed: "
        f"{[(p['VpcPeeringConnectionId'], p['Status']) for p in live]!r}")

    # The data path cannot even be described: the peer's CIDR IS the requester's own CIDR.
    code, message = _error(lambda: ec2.create_route(
        RouteTableId=a["rtb"], DestinationCidrBlock=_B_VPC_CIDR, VpcPeeringConnectionId=pcx))
    assert code == "InvalidParameterValue", (
        f"a route to a destination equal to the VPC's own CIDR must raise exactly "
        f"InvalidParameterValue; got {code!r}")
    assert message == (
        f"The destination CIDR block {_B_VPC_CIDR} is equal to or more specific than one of this "
        f"VPC's CIDR blocks. This route can target only an interface or an instance."), (
        f"unexpected InvalidParameterValue message for the self-CIDR route: {message!r}")
    routes = _routes(ec2, a["rtb"])
    assert not [r for r in routes if r.get("VpcPeeringConnectionId") == pcx], (
        f"the refused route must not be in the table: {routes!r}")
    local_routes = [r for r in routes if r.get("GatewayId") == "local"]
    assert [r["DestinationCidrBlock"] for r in local_routes] == [_A_VPC_CIDR], (
        f"A's own local route must be the only thing claiming the overlapping space: {routes!r}")


def _leg2_nothing_moves_into_the_overlap(ssm, st) -> None:
    a = st["sides"]["a"]
    what = "L2 from A's guest into the overlapping space that no peering can deliver"
    got = _poll(lambda: _json_line(_run_phase(ssm, a["instance"], _client_script(_OVERLAP_IP))),
                lambda r: r["rc"] != 0, timeout_s=180, interval_s=5.0, what=what)
    assert got["rc"] == _CURL_TIMEOUT, (
        f"{what}: the packet must be DROPPED (curl {_CURL_TIMEOUT}), not refused (curl 7): "
        f"{got!r}")
    assert got["body"] == "", f"{what}: something answered, so bytes moved: {got!r}"
    # And the guest that just timed out is demonstrably healthy.
    view = _server_view(ssm, st, a, peer_ip=_OVERLAP_IP)
    assert view["local"] == a["nonce"], (
        f"{what}: A stopped serving, so the timeout is not evidence about the peering: {view!r}")
    assert int(view["hits"]) == 0, (
        f"{what}: A's own log must show no request from the overlapping address: {view!r}")


# ===== L3/L4: the disjoint peer, and its removal ============================
def _leg3_and_4_disjoint_peer_carries_traffic(ctx, ec2, ssm, st) -> None:
    a, c = st["sides"]["a"], st["sides"]["c"]

    pcx = ec2.create_vpc_peering_connection(
        VpcId=a["vpc"], PeerVpcId=c["vpc"],
        TagSpecifications=[{"ResourceType": "vpc-peering-connection",
                            "Tags": _tags_for(st["name"] + "-disjoint")}],
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    st["pcx_ac"] = pcx
    ctx.on_cleanup(lambda: _delete_pcx_if_live(ec2, pcx))
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "pending-acceptance", timeout_s=180,
          interval_s=3.0, what=f"disjoint peering {pcx} reaching pending-acceptance")
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "active", timeout_s=300, interval_s=5.0,
          what=f"disjoint peering {pcx} reaching active")

    _add_peer_route(ec2, a["rtb"], _C_VPC_CIDR, pcx)
    _add_peer_route(ec2, c["rtb"], _A_VPC_CIDR, pcx)
    _poll(lambda: (_route(ec2, a["rtb"], _C_VPC_CIDR), _route(ec2, c["rtb"], _A_VPC_CIDR)),
          lambda pair: all(r is not None and r.get("State") == "active" for r in pair),
          timeout_s=300, interval_s=5.0, what="both peer routes for the disjoint peering going "
                                              "active")

    # --- L3: the positive control, guest-verified in both directions ---------
    before_a = _server_view(ssm, st, a)
    before_c = _server_view(ssm, st, c)
    a_to_c = _reach(ssm, st, a, c, expect_ok=True, what="L3 a -> c over the disjoint peering")
    c_to_a = _reach(ssm, st, c, a, expect_ok=True, what="L3 c -> a over the disjoint peering")
    assert a_to_c["rc"] == 0 and a_to_c["code"] == "200", f"L3: a could not reach c: {a_to_c!r}"
    assert a_to_c["body"] == c["nonce"], (
        f"L3: a reached something that is not c's own payload -- expected {c['nonce']!r}, got "
        f"{a_to_c!r}")
    assert c_to_a["rc"] == 0 and c_to_a["code"] == "200", f"L3: c could not reach a: {c_to_a!r}"
    assert c_to_a["body"] == a["nonce"], (
        f"L3: c reached something that is not a's own payload -- expected {a['nonce']!r}, got "
        f"{c_to_a!r}")
    after_a = _server_view(ssm, st, a)
    after_c = _server_view(ssm, st, c)
    assert int(after_c["hits"]) > int(before_c["hits"]), (
        f"L3: c's own access log must record the request from a ({_A_IP}): "
        f"{before_c['hits']!r} -> {after_c['hits']!r}")
    assert int(after_a["hits"]) > int(before_a["hits"]), (
        f"L3: a's own access log must record the request from c ({_C_IP}): "
        f"{before_a['hits']!r} -> {after_a['hits']!r}")

    # --- L4: delete the peering, touching no route --------------------------
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)
    _poll(lambda: _pcx_status(ec2, pcx), lambda s: s == "deleted", timeout_s=300, interval_s=5.0,
          what=f"disjoint peering {pcx} reaching deleted")
    _poll(lambda: (_route(ec2, a["rtb"], _C_VPC_CIDR), _route(ec2, c["rtb"], _A_VPC_CIDR)),
          lambda pair: all(r is not None and r.get("State") == "blackhole" for r in pair),
          timeout_s=300, interval_s=5.0,
          what="both peer routes reverting to blackhole once the peering was deleted, with no "
               "route rewritten")
    _assert_route_state(ec2, a["rtb"], _C_VPC_CIDR, pcx, "blackhole", "L4 side a")
    _assert_route_state(ec2, c["rtb"], _A_VPC_CIDR, pcx, "blackhole", "L4 side c")

    first_ac = _reach(ssm, st, a, c, expect_ok=False, what="L4 a -> c after the peering was "
                                                           "deleted")
    first_ca = _reach(ssm, st, c, a, expect_ok=False, what="L4 c -> a after the peering was "
                                                           "deleted")
    assert first_ac["rc"] == _CURL_TIMEOUT, (
        f"L4: a DROPPED packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7): a -> c was {first_ac!r}")
    assert first_ca["rc"] == _CURL_TIMEOUT, (
        f"L4: a DROPPED packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7): c -> a was {first_ca!r}")

    # The absence, measured from a baseline taken AFTER convergence: attempts made while the delete
    # was still propagating legitimately DO cross and DO get logged.
    base_a, base_c = _server_view(ssm, st, a), _server_view(ssm, st, c)
    again_ac = _json_line(_run_phase(ssm, a["instance"], _client_script(c["ip"])))
    again_ca = _json_line(_run_phase(ssm, c["instance"], _client_script(a["ip"])))
    for label, got in (("a -> c", again_ac), ("c -> a", again_ca)):
        assert got["rc"] == _CURL_TIMEOUT, (
            f"L4: a second identical attempt must be blocked too, or the block was a transient: "
            f"{label} was {got!r}")
        assert got["body"] == "", f"L4: {label} returned a body, so something answered: {got!r}"
    end_a, end_c = _server_view(ssm, st, a), _server_view(ssm, st, c)
    assert end_a["local"] == a["nonce"], f"L4: a stopped serving: {end_a!r}"
    assert end_c["local"] == c["nonce"], f"L4: c stopped serving: {end_c!r}"
    assert int(end_c["hits"]) == int(base_c["hits"]), (
        f"L4: a blackhole route drops the packet, so c logs no completed request; one further "
        f"blocked attempt moved c's log {base_c['hits']!r} -> {end_c['hits']!r}")
    assert int(end_a["hits"]) == int(base_a["hits"]), (
        f"L4: one further blocked attempt moved a's log {base_a['hits']!r} -> {end_a['hits']!r}")


# ===== in-band teardown =====================================================
def _teardown(ec2, iam, st) -> None:
    """Ordered in-band teardown with waits a registered cleanup cannot afford. Runs every step,
    then raises what it could not remove, carrying any failure in flight."""
    left = []
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i))
    # The disjoint peering is deletable and must go. The overlapping one is NOT: `failed` admits no
    # transition, as L1 asserts, so attempting it would be the one delete guaranteed to fail. It is
    # not billable and AWS expires it; the report names it rather than teardown pretending.
    if st.get("pcx_ac"):
        _step("pcx-disjoint", lambda: _delete_pcx_if_live(ec2, st["pcx_ac"]))
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
        except Exception as exc:  # noqa: BLE001 — collected, raised after the loop
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


def _delete_pcx_if_live(ec2, pcx):
    """Anything already terminal refuses a second delete with InvalidStateTransition, which is not a
    leak; anything live is deleted for real."""
    if _pcx_status(ec2, pcx) in _PCX_DEAD:
        return
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx)


def _assert_vpc_gone(ec2, vpc_id):
    still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    raise AssertionError(f"vpc {vpc_id} is still describable after delete: {still!r}")


_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
               "InvalidVpcPeeringConnectionID.NotFound", "InvalidRoute.NotFound")


def _gone_ok(fn):
    """Second-net cleanup: the in-band teardown usually removed the resource already."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
            raise


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "dpeer-overlapping-cidr"},
            {"Key": "sim2real:managed", "Value": "true"}]


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _retry_dependency(fn, timeout_s=300, interval_s=10):
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


def _bare_vpc(ctx, ec2, st, tag_name, cidr):
    """B: a VPC that exists only to collide with A's address space."""
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(tag_name)}],
    )["Vpc"]["VpcId"]
    st["vpcs"].append(vpc_id)
    ctx.on_cleanup(lambda: _gone_ok(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _side(ctx, ec2, st, key, tag_name, vpc_cidr, sub_cidr, zone, peer_cidr) -> dict:
    """One whole side: a VPC with its own internet gateway, so the SSM control channel that reports
    every verdict never depends on any peering being up."""
    vpc_id = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(tag_name)}],
    )["Vpc"]["VpcId"]
    st["vpcs"].append(vpc_id)
    ctx.on_cleanup(lambda: _gone_ok(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(tag_name)}],
    )["InternetGateway"]["InternetGatewayId"]
    st["igws"].append((vpc_id, igw))
    ctx.on_cleanup(lambda: _gone_ok(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _gone_ok(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)))

    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=sub_cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet)
    ctx.on_cleanup(lambda: _gone_ok(lambda: ec2.delete_subnet(SubnetId=subnet)))

    rtb = _main_route_table(ec2, vpc_id)
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)

    sg = ec2.create_security_group(
        GroupName=tag_name, Description="sim2real dpeer overlapping-cidr side", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(tag_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(lambda: _gone_ok(lambda: ec2.delete_security_group(GroupId=sg)))
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": peer_cidr}]}])

    side = {"vpc": vpc_id, "igw": igw, "subnet": subnet, "rtb": rtb, "sg": sg,
            "ip": _A_IP if key == "a" else _C_IP, "cidr": vpc_cidr, "key": key}
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


def _pcx_status_full(ec2, pcx):
    conns = ec2.describe_vpc_peering_connections(
        VpcPeeringConnectionIds=[pcx])["VpcPeeringConnections"]
    assert len(conns) == 1, f"expected exactly one peering connection for {pcx!r}; got {conns!r}"
    return conns[0]["Status"]


def _pcx_status(ec2, pcx):
    return _pcx_status_full(ec2, pcx)["Code"]


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real dpeer overlapping-cidr control channel",
                    Tags=[{"Key": "sim2real", "Value": "dpeer-overlapping-cidr"}])
    ctx.on_cleanup(lambda: _gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: _gone_ok(lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=_SSM_CORE_POLICY)))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "dpeer-overlapping-cidr"}])
    ctx.on_cleanup(lambda: _gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _gone_ok(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name)))


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
        # Tagged in the same call, so the instance is never untagged and invisible to cleanup.
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume")],
    ), codes=_THROTTLE + ("InvalidParameterValue",), retries=30,
        delay=5.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    ctx.on_cleanup(lambda: _gone_ok(lambda: ec2.terminate_instances(InstanceIds=[iid])))
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
                 timeout_s=timeout_s, interval_s=5.0,
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
CODE=$(curl -s -m 8 -o /tmp/body -w '%{{http_code}}' http://{target_ip}:{_PORT}/nonce)
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


def _server_view(ssm, st, side, peer_ip=None):
    if peer_ip is None:
        peer_ip = st["sides"]["c" if side["key"] == "a" else "a"]["ip"]
    return _json_line(_run_phase(ssm, side["instance"], _server_script(peer_ip)))


def _reach(ssm, st, src, dst, expect_ok, what):
    """Drive one leg from `src` and poll until the expected outcome, so a peering state change that
    has not converged yet is a retry and one that never converges is a FAIL naming what was last
    seen."""
    return _poll(lambda: _json_line(_run_phase(ssm, src["instance"], _client_script(dst["ip"]))),
                 lambda r: (r["rc"] == 0) is expect_ok,
                 timeout_s=300, interval_s=5.0, what=what)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
