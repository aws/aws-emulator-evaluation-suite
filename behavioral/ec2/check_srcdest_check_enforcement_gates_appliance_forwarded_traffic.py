"""srcdest-check-enforcement-gates-appliance-forwarded-traffic."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "srcdest-check-enforcement-gates-appliance-forwarded-traffic"
GROUP = "data-plane"
SERVICES = ["ec2"]

_VPC_CIDR = "10.77.0.0/16"
_SUBNET_CIDR = "10.77.1.0/24"
# m5.large: the family real NAT and firewall appliances run on.
_INSTANCE_TYPE = "m5.large"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

# RFC 5737 TEST-NET-1. Deliberately OUTSIDE _VPC_CIDR and globally non-routable: it can never be
# an address of any ENI in this VPC, which is exactly the property the source/destination check
# tests, and it cannot leak a packet onto the internet if a route is ever wrong.
_VIP = "192.0.2.10"
_PORT = 8080

# Wait ceilings. The expected path is ~600 s; the ceilings sum to a ~1450 s worst case.
_SSM_ONLINE_TIMEOUT_S = 480
_COMMAND_TIMEOUT_S = 180
_CONVERGE_TIMEOUT_S = 120
_TERMINATE_TIMEOUT_S = 420

_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")

# curl exit statuses seen in the client guest:
#   _RC_DROPPED  timed out -- the SYN was silently discarded by the VPC.
#   _RC_REFUSED  the control probe to the appliance's OWN ENI address gets a TCP RST from the guest
#                kernel, proving the packet reached the guest (security group, route and host fine).
_RC_DROPPED = 28
_RC_REFUSED = 7
_HTTP_NONE = "000"
_HTTP_OK = "200"


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """SourceDestCheck is enforced: on, the VPC silently drops traffic for an address not the ENI's
    (while a control to the ENI's own address is refused by the guest); off, the identical
    request reaches the appliance; back on, it is dropped again.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "rt": [], "instances": [], "ip": {}, "eni": {}}
    started = time.monotonic()
    try:
        _build(ctx, ec2, ssm, iam, st)
        _arms(ctx, ec2, ssm, st)
    finally:
        st["elapsed_s"] = round(time.monotonic() - started, 1)
        _teardown(ec2, iam, st)


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-srcdest-")
    st["name"] = name
    st["nonce"] = name

    # Every decidable precondition before the first create: an AZ that cannot run the pinned
    # instance family is an answer available for free, and paying for a VPC to learn it is waste.
    zone = _usable_zone(ec2)
    st["zone"] = zone
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags_for(name)}],
    )["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw_id
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    st["subnet"] = subnet_id
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    # Public addressing on the subnet rather than per-ENI in RunInstances: the SSM control channel
    # then needs no interface endpoints, and one RunInstances call can mint both hosts.
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": _tags_for(name)}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    assoc = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
    st["rt"].append((rt_id, assoc))
    st["rt_id"] = rt_id
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", Description="sim2real source/dest check enforcement",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg_id)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_security_group(GroupId=sg_id)))
    # The appliance port, open to the whole VPC. This is what makes the arm-1 control meaningful:
    # a security group that blocked the port would time out exactly like a source/dest drop, so
    # the group is deliberately permissive and the discrimination is left to the RST.
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": _VPC_CIDR}]}],
    )

    role_name = name + "-role"
    st["role"] = role_name
    st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    # ONE RunInstances for both hosts, and ONE cleanup registration covering both, registered
    # before any readiness poll. Two separate nets would make teardown's clock the SUM of two
    # terminate waits instead of the max, which is how instances survive a cut-off chain.
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=2, MaxCount=2,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": role_name},
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(name)}
                               for rt in ("instance", "volume")],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    ids = sorted(i["InstanceId"] for i in reservation["Instances"])
    assert len(ids) == 2, (
        f"RunInstances with MinCount=2 returned {len(ids)} instances ({ids!r}); this check needs "
        f"exactly two: one forwarder and one client"
    )
    st["instances"] = ids
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.terminate_instances(InstanceIds=list(ids))))
    st["fwd"], st["cli"] = ids[0], ids[1]

    for iid in ids:
        # RunInstances' own response is eventually consistent in DescribeInstances, and a
        # just-launched instance can be returned before its ENI is attached -- so poll for the two
        # fields this check needs rather than indexing into a partial record.
        described = _poll(
            lambda iid=iid: _call_with_retry(
                lambda: ec2.describe_instances(InstanceIds=[iid]),
                codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=12, delay=5.0,
            )["Reservations"][0]["Instances"][0],
            lambda d: bool(d.get("PrivateIpAddress")) and bool(d.get("NetworkInterfaces")),
            timeout_s=180, interval_s=5,
            what=f"DescribeInstances reporting a private address and an ENI for {iid}")
        assert described["InstanceType"] == _INSTANCE_TYPE, (
            f"instance {iid!r} came up as {described['InstanceType']!r}; this row pins "
            f"{_INSTANCE_TYPE!r}, and the behaviour under test only exists on a family that can "
            f"actually forward"
        )
        st["ip"][iid] = described["PrivateIpAddress"]
        st["eni"][iid] = described["NetworkInterfaces"][0]["NetworkInterfaceId"]

    for iid in ids:
        info = _poll(
            lambda iid=iid: _agent_view(ssm, iid),
            lambda i: i is not None and i.get("PingStatus") == "Online",
            timeout_s=_SSM_ONLINE_TIMEOUT_S, interval_s=10,
            what=f"the SSM agent on {iid} coming Online")
        assert info["PingStatus"] == "Online", f"agent view for {iid} was {info!r}"


# ===== the three arms =======================================================
def _arms(ctx, ec2, ssm, st) -> None:
    fwd, cli = st["fwd"], st["cli"]
    fwd_eni, fwd_ip, cli_ip = st["eni"][fwd], st["ip"][fwd], st["ip"][cli]
    nonce = st["nonce"]

    # --- the route that sends non-local traffic at the forwarder's ENI -------
    ec2.create_route(RouteTableId=st["rt_id"], DestinationCidrBlock=f"{_VIP}/32",
                     NetworkInterfaceId=fwd_eni)
    route = _vip_route(ec2, st["rt_id"])
    assert route["NetworkInterfaceId"] == fwd_eni, (
        f"the {_VIP}/32 route must target the forwarder's ENI {fwd_eni!r}; the table holds "
        f"{route!r}"
    )
    assert route["State"] == "active", (
        f"the {_VIP}/32 -> {fwd_eni!r} route is in state {route['State']!r}, expected 'active'; a "
        f"blackhole route would drop the packet for a reason that is not the source/dest check"
    )

    # --- the DEFAULT state of the attribute, read two independent ways ------
    assert _instance_srcdest(ec2, fwd) is True, (
        f"a freshly launched instance must enforce source/destination checking; "
        f"DescribeInstanceAttribute reports {_instance_srcdest(ec2, fwd)!r} for {fwd!r}"
    )
    assert _eni_srcdest(ec2, fwd_eni) is True, (
        f"DescribeNetworkInterfaceAttribute reports {_eni_srcdest(ec2, fwd_eni)!r} for the "
        f"forwarder's ENI {fwd_eni!r}, but DescribeInstanceAttribute reports enforcement on; the "
        f"two views of one attribute must agree"
    )

    # --- the appliance: a listener bound to an address that is NOT the ENI's -
    setup = _run_phase(ssm, fwd, _appliance_script())
    boot = _payload_json(setup)
    assert setup["ResponseCode"] == 0, (
        f"bringing the appliance up inside {fwd!r} failed rc={setup['ResponseCode']!r}: {boot!r}"
    )
    assert f"{_VIP}/32" in boot["lo_addrs"], (
        f"the forwarder guest does not hold {_VIP}/32 on loopback; `ip addr` reported "
        f"{boot['lo_addrs']!r}, so it could not answer a packet for it even if one arrived"
    )
    assert boot["listening"] == f"{_VIP}:{_PORT}", (
        f"the appliance must be bound to {_VIP}:{_PORT} and nothing else; `ss -ltn` inside the "
        f"guest reported {boot['listening']!r}. Binding the wildcard address would make the "
        f"control probe to the forwarder's own address succeed and destroy the attribution"
    )
    assert boot["ip_forward"] == "1", (
        f"the forwarder guest reports net.ipv4.ip_forward={boot['ip_forward']!r}, expected '1'"
    )
    assert boot["iid"] == fwd, (
        f"the forwarder guest read instance id {boot['iid']!r} out of IMDSv2; RunInstances "
        f"returned {fwd!r}"
    )

    # --- ARM 1: enforcement ON (the default). The packet never arrives ------
    neg = _client(ssm, cli, fwd_ip, f"{nonce}-neg")
    assert neg["iid"] == cli, (
        f"the client guest read instance id {neg['iid']!r} out of IMDSv2; RunInstances returned "
        f"{cli!r}. Nothing below is evidence about the network unless the host ran the command"
    )
    assert neg["vip_rc"] == _RC_DROPPED, (
        f"with SourceDestCheck enabled on {fwd!r}, the request to {_VIP}:{_PORT} exited "
        f"{neg['vip_rc']!r} inside the client guest; expected curl's timeout status "
        f"{_RC_DROPPED} -- a SILENTLY DISCARDED packet. stderr: {neg['vip_err']!r}"
    )
    assert neg["vip_code"] == _HTTP_NONE, (
        f"the client guest recorded HTTP status {neg['vip_code']!r} for {_VIP}:{_PORT} with "
        f"enforcement on; expected {_HTTP_NONE!r} (no connection at all). Body: "
        f"{neg['vip_body']!r}"
    )
    # The control that makes the absence attributable. Same guest, same port, same security
    # group, same instant -- only the destination address differs, and THAT one is the ENI's own.
    assert neg["own_rc"] == _RC_REFUSED, (
        f"the control probe from {cli!r} to the forwarder's OWN address {fwd_ip}:{_PORT} exited "
        f"{neg['own_rc']!r}, expected curl's connection-refused status {_RC_REFUSED}. A refusal "
        f"is a TCP reset from the forwarder's kernel, which is the only evidence that the "
        f"security group is open, the host is up and the path is live; without it the timeout "
        f"above proves nothing about the source/dest check. stderr: {neg['own_err']!r}"
    )

    # The FAR END, read in-guest: the appliance never saw it.
    far_neg = _far_end(ssm, fwd)
    assert far_neg["alive"] == "yes", (
        f"the appliance process is no longer running inside {fwd!r} ({far_neg!r}); a dead server "
        f"would explain the absence above without any source/dest check being involved"
    )
    assert far_neg["listening"] == f"{_VIP}:{_PORT}", (
        f"the appliance is no longer bound to {_VIP}:{_PORT} inside {fwd!r}; `ss -ltn` reported "
        f"{far_neg['listening']!r}"
    )
    assert far_neg["arrivals"] == [], (
        f"the appliance's own log inside {fwd!r} records arrivals {far_neg['arrivals']!r} while "
        f"SourceDestCheck was enabled; a packet whose destination {_VIP} is not an address of "
        f"ENI {fwd_eni!r} must be discarded by the VPC and must never reach the guest"
    )

    # --- ARM 2: flip exactly ONE thing -------------------------------------
    ec2.modify_instance_attribute(InstanceId=fwd, SourceDestCheck={"Value": False})
    ctx.on_cleanup(lambda: _restore_srcdest(ctx, fwd))
    assert _instance_srcdest(ec2, fwd) is False, (
        f"after ModifyInstanceAttribute(SourceDestCheck=False), DescribeInstanceAttribute still "
        f"reports {_instance_srcdest(ec2, fwd)!r} for {fwd!r}; the arm below cannot mean anything "
        f"until the mutation has landed"
    )
    assert _eni_srcdest(ec2, fwd_eni) is False, (
        f"the instance-level flip did not reach the attached ENI {fwd_eni!r}: "
        f"DescribeNetworkInterfaceAttribute reports {_eni_srcdest(ec2, fwd_eni)!r}. The ENI is "
        f"where the VPC enforces, so an instance-level write that does not propagate is the defect"
    )

    # A bounded retry, legitimate on THIS arm only: nothing documents the attribute change as
    # synchronous with the dataplane. Arm 1 and arm 3 get no retry.
    pos = _poll(lambda: _client(ssm, cli, fwd_ip, f"{nonce}-pos"),
                lambda p: p["vip_rc"] == 0,
                timeout_s=_CONVERGE_TIMEOUT_S, interval_s=10,
                what=f"the identical request to {_VIP}:{_PORT} succeeding once SourceDestCheck "
                     f"is disabled on {fwd!r}")
    assert pos["vip_rc"] == 0, (
        f"with SourceDestCheck DISABLED on {fwd!r}, the identical request to {_VIP}:{_PORT} still "
        f"exited {pos['vip_rc']!r} within {_CONVERGE_TIMEOUT_S}s. stderr: {pos['vip_err']!r}"
    )
    assert pos["vip_code"] == _HTTP_OK, (
        f"the client guest recorded HTTP status {pos['vip_code']!r}, expected {_HTTP_OK!r}. Body: "
        f"{pos['vip_body']!r}"
    )
    # The appliance composed this body, so the client is quoting the far end back at us.
    assert pos["vip_body"].strip() == f"appliance-ok path=/{nonce}-pos peer={cli_ip}", (
        f"the body the client guest received from {_VIP}:{_PORT} was {pos['vip_body']!r}; the "
        f"appliance composes it from the request path and the peer address it observed, so it "
        f"must read 'appliance-ok path=/{nonce}-pos peer={cli_ip}'"
    )
    assert pos["own_rc"] == _RC_REFUSED, (
        f"disabling the source/dest check must not make the forwarder's own address answer on "
        f"{_PORT}; the control probe to {fwd_ip}:{_PORT} exited {pos['own_rc']!r}, expected "
        f"{_RC_REFUSED}. stderr: {pos['own_err']!r}"
    )

    # The FAR END, read in-guest: the keystone. The appliance saw this one, and it still has not
    # seen arm 1's -- which is what separates "dropped" from "delivered late".
    #
    # Asserted as SETS rather than as an exact list because arm 2 is the one arm that retries: a
    # request that arrived but whose reply was dropped mid-convergence would log a second
    # identical line, which says nothing about fidelity. What must hold exactly is WHICH paths
    # arrived and from WHOM -- the arm-2 path, from the client, and nothing else ever.
    far_pos = _far_end(ssm, fwd)
    assert sorted({p for p, _ in far_pos["arrivals"]}) == [f"/{nonce}-pos"], (
        f"the appliance's own log inside {fwd!r} records arrivals {far_pos['arrivals']!r}; with "
        f"the source/dest check disabled it must record the arm-2 path '/{nonce}-pos' and nothing "
        f"else -- in particular it must STILL record nothing for '/{nonce}-neg', because a packet "
        f"the VPC discarded cannot arrive later"
    )
    assert sorted({peer for _, peer in far_pos["arrivals"]}) == [cli_ip], (
        f"the appliance saw peers {far_pos['arrivals']!r}; the only host that sent anything is the "
        f"client {cli!r} at {cli_ip}, and the peer address the far end observed is the evidence "
        f"that the VPC forwarded the frame rather than rewriting or originating it"
    )

    # --- ARM 3: put it back, and the traffic must stop again ----------------
    ec2.modify_instance_attribute(InstanceId=fwd, SourceDestCheck={"Value": True})
    assert _eni_srcdest(ec2, fwd_eni) is True, (
        f"re-enabling enforcement did not reach ENI {fwd_eni!r}: "
        f"DescribeNetworkInterfaceAttribute reports {_eni_srcdest(ec2, fwd_eni)!r}"
    )
    # Convergence first, on a THROWAWAY path, so the final absence can be asserted exactly. The
    # window between the API write and the dataplane enforcing it is not documented as
    # synchronous, and a request that slips through it is a timing fact about the re-arm rather
    # than a fidelity fact about the switch.
    _poll(lambda: _client(ssm, cli, fwd_ip, f"{nonce}-settle"),
          lambda p: p["vip_rc"] != 0,
          timeout_s=_CONVERGE_TIMEOUT_S, interval_s=10,
          what=f"the request to {_VIP}:{_PORT} being discarded again once SourceDestCheck is "
               f"re-enabled on {fwd!r}")
    # Now the log is cleared and ONE un-retried request is sent, so "nothing arrived" is exact.
    cleared = _reset_far_end_log(ssm, fwd)
    assert cleared["alive"] == "yes" and cleared["listening"] == f"{_VIP}:{_PORT}", (
        f"the appliance must still be running and bound to {_VIP}:{_PORT} before the final arm; "
        f"the forwarder guest reported {cleared!r}"
    )
    assert cleared["arrivals"] == [], (
        f"the appliance log was not actually cleared inside {fwd!r}: it still reports "
        f"{cleared['arrivals']!r}, so an absence measured against it would be meaningless"
    )

    rearm = _client(ssm, cli, fwd_ip, f"{nonce}-rearm")
    assert rearm["vip_rc"] == _RC_DROPPED, (
        f"with SourceDestCheck re-enabled on {fwd!r}, the identical request exited "
        f"{rearm['vip_rc']!r}, expected {_RC_DROPPED}; the switch must be reversible, or arm 2 "
        f"measured something that happened once rather than the attribute. stderr: "
        f"{rearm['vip_err']!r}"
    )
    assert rearm["vip_code"] == _HTTP_NONE, (
        f"the client guest recorded HTTP status {rearm['vip_code']!r} for {_VIP}:{_PORT} in the "
        f"re-armed state; expected {_HTTP_NONE!r}. Body: {rearm['vip_body']!r}"
    )
    assert rearm["own_rc"] == _RC_REFUSED, (
        f"the control probe to {fwd_ip}:{_PORT} exited {rearm['own_rc']!r} in the re-armed state, "
        f"expected {_RC_REFUSED}; the path must still be live for the drop to be attributable. "
        f"stderr: {rearm['own_err']!r}"
    )

    far_rearm = _far_end(ssm, fwd)
    assert far_rearm["arrivals"] == [], (
        f"the appliance's own log inside {fwd!r} records arrivals {far_rearm['arrivals']!r} after "
        f"enforcement was re-enabled and the log cleared; the re-armed request must have been "
        f"discarded by the VPC and must never have reached the guest"
    )
    assert far_rearm["alive"] == "yes", (
        f"the appliance process died before the final read inside {fwd!r} ({far_rearm!r}), so the "
        f"re-armed absence is not attributable to the source/dest check"
    )
    assert far_rearm["listening"] == f"{_VIP}:{_PORT}", (
        f"the appliance is no longer bound to {_VIP}:{_PORT} inside {fwd!r} at the final read; "
        f"`ss -ltn` reported {far_rearm['listening']!r}"
    )


# ===== in-band teardown =====================================================
def _teardown(ec2, iam, st) -> None:
    """Ordered in-band teardown with waits a bounded cleanup cannot afford; raises naming what it
    could not remove (and any in-flight error). Instances go first: nothing in the VPC can be
    deleted while their ENIs are attached.
    """
    steps = []
    if st.get("instances"):
        steps.append(("instances", lambda: _terminate_and_wait(ec2, st["instances"])))
    if st.get("vpc"):
        steps.append(("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=300, interval_s=2.0,
            what=f"every ENI in {st['vpc']!r} draining after the instances terminated")))
    for sg in st.get("sgs", []):
        steps.append((f"sg {sg}", lambda sg=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=sg))))
    for rt_id, assoc in st.get("rt", []):
        steps.append((f"rt-assoc {assoc}", lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
        steps.append((f"rt {rt_id}", lambda r=rt_id: _retry_dependency(
            lambda: ec2.delete_route_table(RouteTableId=r))))
    for subnet in st.get("subnets", []):
        steps.append((f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s))))
    if st.get("igw"):
        steps.append(("igw", lambda: _detach_and_delete_igw(ec2, st["igw"], st["vpc"])))
    if st.get("vpc"):
        steps.append(("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"]))))
        # Verified absence, not a delete that returned 200.
        steps.append(("vpc-gone", lambda: _assert_vpc_gone(ec2, st["vpc"])))
    if st.get("profile"):
        steps.append(("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"])))
    if st.get("role"):
        steps.append(("role", lambda: _drop_role(iam, st["role"])))
    left = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 — collected, raised below
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        prefix = f"{found!r}; " if found is not None else ""
        raise AssertionError(f"{prefix}teardown could not remove everything the check created: {left!r}")


def _assert_vpc_gone(ec2, vpc_id) -> None:
    """A deleted VPC answers InvalidVpcID.NotFound; anything else means it is still there."""
    try:
        still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidVpcID.NotFound":
            raise
        return
    raise AssertionError(f"vpc {vpc_id} is still describable: {still!r}")


# ===== helpers ==============================================================
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidGroup.NotFound",
               "InvalidInternetGatewayID.NotFound", "InvalidInstanceID.NotFound",
               "InvalidAssociationID.NotFound", "InvalidRoute.NotFound")


def _unless_gone(fn) -> None:
    """A registered cleanup: the in-band teardown in run() deletes the same resources first, so a
    not-found answer here is done; any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
            raise


def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "srcdest-check-enforcement"},
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


def _usable_zone(ec2):
    """The first AZ that both OFFERS the pinned instance type and is `available`."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offerings were "
        f"{sorted(offered)!r}")
    return usable[0]


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real source/dest check enforcement",
                    Tags=[{"Key": "sim2real", "Value": "srcdest-check-enforcement"}])
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "srcdest-check-enforcement"}])
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _unless_gone(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name)))
    # IAM exposes no "this role is usable" condition to poll. Correctness comes entirely from
    # RunInstances' own bounded retry on InvalidParameterValue, above -- no separate wait here.


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


def _terminate_and_wait(ec2, instance_ids, timeout_s=_TERMINATE_TIMEOUT_S):
    """Issue every terminate FIRST, then wait once. One net for the whole set, so the cost is the
    max of the two shutdowns rather than their sum."""
    ec2.terminate_instances(InstanceIds=list(instance_ids))
    deadline = time.monotonic() + timeout_s
    states = {}
    while time.monotonic() < deadline:
        states = {i["InstanceId"]: i["State"]["Name"]
                  for r in _call_with_retry(
                      lambda: ec2.describe_instances(InstanceIds=list(instance_ids)),
                      codes=_THROTTLE + ("InvalidInstanceID.NotFound",),
                      retries=12, delay=5.0)["Reservations"]
                  for i in r["Instances"]}
        if all(s == "terminated" for s in states.values()):
            return
        time.sleep(2)
    raise AssertionError(
        f"instances {list(instance_ids)!r} never all reached terminated within {timeout_s}s "
        f"(last states {states!r})")


def _vpc_enis(ec2, vpc_id):
    found = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        found += [e["NetworkInterfaceId"] for e in page["NetworkInterfaces"]]
    return found


def _retry_dependency(fn, timeout_s=240, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _detach_and_delete_igw(ec2, igw_id, vpc_id):
    try:
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "Gateway.NotAttached":
            raise
    _retry_dependency(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))


def _vip_route(ec2, rt_id):
    table = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]
    hits = [r for r in table["Routes"] if r.get("DestinationCidrBlock") == f"{_VIP}/32"]
    assert len(hits) == 1, (
        f"route table {rt_id!r} holds {len(hits)} routes for {_VIP}/32, expected exactly one. "
        f"Routes: {table['Routes']!r}"
    )
    return hits[0]


def _instance_srcdest(ec2, instance_id):
    return ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="sourceDestCheck")["SourceDestCheck"]["Value"]


def _eni_srcdest(ec2, eni_id):
    return ec2.describe_network_interface_attribute(
        NetworkInterfaceId=eni_id, Attribute="sourceDestCheck")["SourceDestCheck"]["Value"]


def _restore_srcdest(ctx, instance_id):
    """Failure-path net: re-enable the check if a failure aborts before arm 3 puts it back. An
    instance the in-band teardown already terminated is done."""
    ec2 = ctx.client("ec2")
    try:
        ec2.modify_instance_attribute(InstanceId=instance_id, SourceDestCheck={"Value": True})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in _GONE_CODES:
            return
        if code == "IncorrectInstanceState" and _instance_state(ec2, instance_id) in (
                "shutting-down", "terminated"):
            return
        raise


def _instance_state(ec2, instance_id):
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    return reservations[0]["Instances"][0]["State"]["Name"]


def _agent_view(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _run_phase(ssm, instance_id, script, timeout_s=_COMMAND_TIMEOUT_S):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment=CHECK[:100]))
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
                 what=f"invocation {command_id} on {instance_id} reaching a terminal status")


def _payload_json(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout at all: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


def _client(ssm, instance_id, fwd_ip, path):
    """One client-side probe pair, read out of the client guest's own stdout: the request to the
    VIP the route sends at the forwarder's ENI, and the control request to the forwarder's own
    address on the same port."""
    inv = _run_phase(ssm, instance_id, _client_script(fwd_ip, path))
    payload = _payload_json(inv)
    assert inv["ResponseCode"] == 0, (
        f"the client probe script itself failed rc={inv['ResponseCode']!r} on {instance_id!r}; "
        f"it reports curl's status in its payload and must always exit 0. payload={payload!r} "
        f"stderr={inv['StandardErrorContent'][:300]!r}"
    )
    return {"vip_rc": int(payload["VIPRC"]), "own_rc": int(payload["OWNRC"]),
            "vip_code": payload["vip_code"], "own_code": payload["own_code"],
            "vip_body": payload["vip_body"], "vip_err": payload["vip_err"],
            "own_err": payload["own_err"], "iid": payload["IID"], "myip": payload["MYIP"]}


def _far_end(ssm, instance_id, prelude="true"):
    """The far end, read inside the forwarder guest: the appliance's logged arrivals as
    (path, peer) pairs, and whether it is still running and bound.
    """
    inv = _run_phase(ssm, instance_id, _far_end_script(prelude))
    payload = _payload_json(inv)
    assert inv["ResponseCode"] == 0, (
        f"reading the appliance state inside {instance_id!r} failed rc={inv['ResponseCode']!r}: "
        f"payload={payload!r} stderr={inv['StandardErrorContent'][:300]!r}"
    )
    arrivals = []
    for line in payload["log"].splitlines():
        if not line.startswith("ARRIVED "):
            continue
        fields = dict(part.split("=", 1) for part in line[len("ARRIVED "):].split() if "=" in part)
        arrivals.append((fields.get("path"), fields.get("peer")))
    return {"arrivals": arrivals, "alive": payload["ALIVE"], "listening": payload["LISTEN"],
            "log": payload["log"], "iid": payload["IID"]}


def _reset_far_end_log(ssm, instance_id):
    """Truncate the appliance's arrival log in-guest and read the state back.

    Arrivals logged while re-enabled enforcement converges are timing, not the attribute.
    """
    return _far_end(ssm, instance_id, prelude=": > /tmp/appliance.log")


# The appliance. Bound to @VIP@ ONLY -- never the wildcard -- because the control probe to the
# forwarder's own address must stay refused in every arm, and a wildcard bind would answer it.
_APPLIANCE_PY = """import http.server, socketserver, sys

VIP = sys.argv[1]
PORT = int(sys.argv[2])


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        peer = self.client_address[0]
        body = ("appliance-ok path=" + self.path + " peer=" + peer + "\\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print("ARRIVED path=" + self.path + " peer=" + peer, flush=True)

    def log_message(self, fmt, *args):
        return


socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer((VIP, PORT), Handler).serve_forever()
"""

# Placeholders rather than an f-string: these scripts contain curl's `%{http_code}` and shell
# `${...}`, and escaping every brace for str.format makes them unreadable.
_APPLIANCE_SH = """set -uo pipefail
sysctl -w net.ipv4.ip_forward=1 >/dev/null
# Per-interface, because rp_filter is an OR of `all` and the device's own knob: a frame addressed
# to the loopback VIP arrives on eth0 and would otherwise be dropped by the HOST, which would make
# the drop unattributable to the source/dest check.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done
ip addr replace @VIP@/32 dev lo
cat > /tmp/appliance.py <<'PYEOF'
@APPLIANCE_PY@
PYEOF
: > /tmp/appliance.log
setsid nohup python3 -u /tmp/appliance.py @VIP@ @PORT@ >/tmp/appliance.log 2>&1 </dev/null &
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qx '@VIP@:@PORT@'; then break; fi
  sleep 1
done
FWD=$(cat /proc/sys/net/ipv4/ip_forward)
LO=$(ip -o -4 addr show dev lo | tr -s ' ' | cut -d' ' -f4 | paste -sd,)
# Filtered to OUR port: an unfiltered `ss` also reports sshd and chrony, which says nothing about
# the appliance and would make an exact assertion on the bind address impossible.
LISTEN=$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep ':@PORT@$' | paste -sd,)
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
-H "X-aws-ec2-metadata-token-ttl-seconds: 300")
IID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
http://169.254.169.254/latest/meta-data/instance-id)
export FWD LO LISTEN IID
python3 - <<'JEOF'
import json, os
print(json.dumps(dict(ip_forward=os.environ["FWD"], lo_addrs=os.environ["LO"],
                      listening=os.environ["LISTEN"], iid=os.environ["IID"])))
JEOF
exit 0
"""

_CLIENT_SH = """set -uo pipefail
curl -sS -m 12 -o /tmp/vip.body -w '%{http_code}' \
http://@VIP@:@PORT@/@PATH@ >/tmp/vip.code 2>/tmp/vip.err
VIPRC=$?
curl -sS -m 12 -o /tmp/own.body -w '%{http_code}' \
http://@FWDIP@:@PORT@/@PATH@-own >/tmp/own.code 2>/tmp/own.err
OWNRC=$?
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
-H "X-aws-ec2-metadata-token-ttl-seconds: 300")
IID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
http://169.254.169.254/latest/meta-data/instance-id)
MYIP=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
http://169.254.169.254/latest/meta-data/local-ipv4)
export VIPRC OWNRC IID MYIP
python3 - <<'JEOF'
import json, os
out = dict((k, os.environ.get(k, "")) for k in ("VIPRC", "OWNRC", "IID", "MYIP"))
for field, path in (("vip_code", "/tmp/vip.code"), ("vip_body", "/tmp/vip.body"),
                    ("vip_err", "/tmp/vip.err"), ("own_code", "/tmp/own.code"),
                    ("own_err", "/tmp/own.err")):
    try:
        with open(path) as fh:
            out[field] = fh.read()[-400:]
    except OSError:
        out[field] = ""
print(json.dumps(out))
JEOF
exit 0
"""

_FAR_END_SH = """set -uo pipefail
@PRELUDE@
if pgrep -f '/tmp/appliance.py' >/dev/null 2>&1; then ALIVE=yes; else ALIVE=no; fi
LISTEN=$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep ':@PORT@$' | paste -sd,)
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
-H "X-aws-ec2-metadata-token-ttl-seconds: 300")
IID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
http://169.254.169.254/latest/meta-data/instance-id)
export ALIVE LISTEN IID
python3 - <<'JEOF'
import json, os
out = dict((k, os.environ.get(k, "")) for k in ("ALIVE", "LISTEN", "IID"))
try:
    with open("/tmp/appliance.log") as fh:
        out["log"] = fh.read()[-4000:]
except OSError:
    out["log"] = ""
print(json.dumps(out))
JEOF
exit 0
"""


def _fill(template, **subs):
    out = template
    for key, value in subs.items():
        out = out.replace("@" + key + "@", str(value))
    assert "@" not in out, f"unsubstituted placeholder left in {out[:200]!r}"
    return out


def _appliance_script():
    return _fill(_APPLIANCE_SH, APPLIANCE_PY=_APPLIANCE_PY.rstrip("\n"), VIP=_VIP, PORT=_PORT)


def _client_script(fwd_ip, path):
    return _fill(_CLIENT_SH, VIP=_VIP, PORT=_PORT, PATH=path, FWDIP=fwd_ip)


def _far_end_script(prelude="true"):
    return _fill(_FAR_END_SH, PRELUDE=prelude, PORT=_PORT)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
