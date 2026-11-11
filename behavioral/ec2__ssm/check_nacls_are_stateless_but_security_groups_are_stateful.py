"""nacls-are-stateless-but-security-groups-are-stateful."""
from __future__ import annotations

import base64
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nacls-are-stateless-but-security-groups-are-stateful"
GROUP = "data-plane"
SERVICES = ["ec2", "ssm"]

_VPC_CIDR = "10.71.0.0/16"
_CLIENT_CIDR = "10.71.10.0/24"
_SERVER_CIDR = "10.71.11.0/24"
_ENDPOINT_CIDR = "10.71.20.0/24"
_SERVER_IP = "10.71.11.10"
_PORT = 8080
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
# curl(1): 28 is "Operation timeout", 7 is "Failed to connect". A silently DROPPED packet gives
# 28; a refused connection gives 7. Every blocked leg here is 28: the packets are dropped.
_CURL_TIMEOUT = 28


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A NACL is stateless and a security group stateful: with inbound tcp/8080 allowed, a NACL
    egress deny on the return path drops the connection while a narrowed SG egress still lets it
    through; NACL entries match by rule number.

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"iface": [], "subnets": [], "sgs": [], "acls": [], "restore_assoc": [],
                "instances": []}
    # Teardown runs in-band in `finally`: waiting for instances and endpoint ENIs to drain
    # outlasts the registered-cleanup budget; ctx.on_cleanup is the fast second net.
    try:
        _build(ctx, ec2, ssm, iam, st)
        _legs(ec2, ssm, st, ctx=ctx)
    finally:
        _teardown(ec2, iam, st, ctx=ctx)


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    region = ctx.region
    name = ctx.unique_name("sim2real-b1nacl-")
    st["name"], st["region"], st["nonce"] = name, region, name

    zones = _usable_zones(ec2, want=2)
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    # No internet gateway and no route table of our own: the VPC's main route table carries only
    # the local route, so the two instances can reach each other and nothing else, and every
    # observation below is about the VPC's own filtering rather than about egress to the internet.

    client_subnet = _create_subnet(ctx, ec2, st, _CLIENT_CIDR, zones[0], name + "-client")
    server_subnet = _create_subnet(ctx, ec2, st, _SERVER_CIDR, zones[1], name + "-server")
    endpoint_subnet = _create_subnet(ctx, ec2, st, _ENDPOINT_CIDR, zones[0], name + "-endpoint")
    st["client_subnet"], st["server_subnet"] = client_subnet, server_subnet

    sg_ep = _create_sg(ctx, ec2, st, name + "-endpoint", "sim2real b1 interface endpoints")
    ec2.authorize_security_group_ingress(
        GroupId=sg_ep,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": _VPC_CIDR}]}])
    sg_client = _create_sg(ctx, ec2, st, name + "-client", "sim2real b1 client")
    sg_server = _create_sg(ctx, ec2, st, name + "-server", "sim2real b1 server")
    st["sg_server"] = sg_server
    ec2.authorize_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": _VPC_CIDR}]}])

    for svc in ("ssm", "ssmmessages", "ec2messages"):
        ep = ec2.create_vpc_endpoint(
            VpcEndpointType="Interface", VpcId=vpc_id,
            ServiceName=f"com.amazonaws.{region}.{svc}",
            SubnetIds=[endpoint_subnet], SecurityGroupIds=[sg_ep], PrivateDnsEnabled=True,
            TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": _tags_for(name)}],
        )["VpcEndpoint"]["VpcEndpointId"]
        st["iface"].append(ep)
        ctx.on_cleanup(lambda ep=ep: ec2.delete_vpc_endpoints(VpcEndpointIds=[ep]))
    for ep in st["iface"]:
        _poll(lambda ep=ep: _endpoint_state(ec2, ep), lambda s: s == "available",
              timeout_s=420, interval_s=2, what=f"interface endpoint {ep} becoming available",
              ctx=ctx)

    # custom NACLs, allow-all to start, associated in place of the default one
    st["acl_client"] = _attach_permissive_acl(ctx, ec2, st, client_subnet, name + "-client-acl")
    st["acl_server"] = _attach_permissive_acl(ctx, ec2, st, server_subnet, name + "-server-acl")

    role_name = name + "-role"
    st["role"] = st["profile"] = role_name
    _create_instance_role(ctx, iam, role_name)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    server_user_data = (
        "#!/bin/bash\n"
        "mkdir -p /tmp/srv\n"
        f"printf '%s' '{st['nonce']}' > /tmp/srv/nonce\n"
        "cd /tmp/srv\n"
        f"nohup python3 -m http.server {_PORT} --bind 0.0.0.0 > /tmp/httpd.log 2>&1 &\n"
    )
    st["server"] = _launch(ctx, ec2, st, ami, server_subnet, sg_server, name + "-server",
                           user_data=server_user_data, private_ip=_SERVER_IP)
    st["client"] = _launch(ctx, ec2, st, ami, client_subnet, sg_client, name + "-client")

    for label, iid in (("server", st["server"]), ("client", st["client"])):
        info = _poll(lambda iid=iid: _agent_view(ssm, iid),
                     lambda i: i is not None and i.get("PingStatus") == "Online",
                     timeout_s=600, interval_s=2,
                     what=f"the SSM agent on the {label} {iid} coming Online through the "
                          f"interface endpoints {st['iface']!r}", ctx=ctx)
        assert info["PingStatus"] == "Online", f"the {label}'s agent view was {info!r}"

    # RunInstances is eventually consistent: DescribeInstances can 404 an id it has just minted.
    described = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=[st["server"], st["client"]]),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=30, delay=2.0)["Reservations"]
    by_id = {i["InstanceId"]: i for r in described for i in r["Instances"]}
    assert by_id[st["server"]]["PrivateIpAddress"] == _SERVER_IP, (
        f"the server did not take the fixed address the legs target: "
        f"{by_id[st['server']]['PrivateIpAddress']!r}")
    st["client_ip"] = by_id[st["client"]]["PrivateIpAddress"]
    assert by_id[st["client"]]["Placement"]["AvailabilityZone"] != \
        by_id[st["server"]]["Placement"]["AvailabilityZone"], (
        "the two instances must sit in different AZs, so the legs also exercise cross-AZ intra-VPC "
        f"delivery; they are in {by_id[st['client']]['Placement']!r} and "
        f"{by_id[st['server']]['Placement']!r}")

    # The ephemeral source-port range is READ OUT OF THE GUEST, never hardcoded: the L2 rule is
    # built from what this kernel actually uses, so the leg cannot silently stop testing anything.
    ports = _stdout(_run_phase(ssm, st["client"], "cat /proc/sys/net/ipv4/ip_local_port_range\n",
                               ctx=ctx))
    lo, hi = (int(x) for x in ports.split())
    assert 1024 <= lo < hi <= 65535, f"implausible ephemeral range read from the guest: {ports!r}"
    st["ephemeral"] = (lo, hi)


# ===== the six legs =========================================================
def _legs(ec2, ssm, st, *, ctx) -> None:
    lo, hi = st["ephemeral"]
    acl_server = st["acl_server"]

    # --- the barrier: nothing below is interpretable unless the server serves ---
    local = _server_view(ssm, st, ctx=ctx)
    assert local["local"] == st["nonce"], (
        f"the server must answer its own listener on 127.0.0.1 before any leg runs; it returned "
        f"{local['local']!r}, expected {st['nonce']!r}")
    hits0 = int(local["hits"])

    # --- L1: allow-all NACLs, allow-all SG egress -----------------------------
    l1 = _reach(ssm, st, expect_ok=True, what="L1 baseline with allow-all NACLs", ctx=ctx)
    assert l1["rc"] == 0 and l1["code"] == "200", f"L1 did not reach the server: {l1!r}"
    assert l1["body"] == st["nonce"], (
        f"L1 reached something that is not the server's own payload: {l1!r}")
    after_l1 = _server_view(ssm, st, ctx=ctx)
    hits1 = int(after_l1["hits"])
    assert hits1 > hits0, (
        f"the server's access log must record L1's request from {st['client_ip']!r}: "
        f"{hits0!r} -> {hits1!r}")

    # --- L2: stateless proof -- deny the RETURN path only ---------------------
    ec2.create_network_acl_entry(
        NetworkAclId=acl_server, RuleNumber=50, Protocol="6", RuleAction="deny", Egress=True,
        CidrBlock=_CLIENT_CIDR, PortRange={"From": lo, "To": hi})
    entry = _acl_entry(ec2, acl_server, 50, egress=True)
    assert entry["RuleAction"] == "deny" and entry["Protocol"] == "6", f"L2 entry is {entry!r}"
    assert entry["PortRange"] == {"From": lo, "To": hi}, (
        f"the L2 rule must cover exactly the ephemeral range read from the guest "
        f"{(lo, hi)!r}; the entry says {entry!r}")
    assert entry["CidrBlock"] == _CLIENT_CIDR, f"L2 entry targets {entry!r}"
    ingress_allow = _acl_entry(ec2, acl_server, 100, egress=False)
    assert ingress_allow["RuleAction"] == "allow", (
        f"the server's NACL must still ALLOW the request inbound, otherwise L2 proves nothing "
        f"about statelessness: {ingress_allow!r}")

    l2, base2, after2 = _blocked_leg(
        ssm, st, what="L2 with the server's NACL egress denying the client's ephemeral range",
        ctx=ctx)
    assert l2["body"] == "", f"L2 returned a body, so something answered: {l2!r}"
    # the server is alive: it answers itself, and its own control channel still works
    assert after2["local"] == st["nonce"], (
        f"the server stopped serving, so L2 is not evidence about the return path: {after2!r}")
    assert int(after2["hits"]) == int(base2["hits"]), (
        f"a NACL egress deny blocks the SYN-ACK, so the connection never establishes and the "
        f"server logs no completed request; one further blocked attempt moved the log "
        f"{base2['hits']!r} -> {after2['hits']!r}")

    # --- L3: restore the return path -----------------------------------------
    ec2.delete_network_acl_entry(NetworkAclId=acl_server, RuleNumber=50, Egress=True)
    l3 = _reach(ssm, st, expect_ok=True, what="L3 after the egress deny was removed", ctx=ctx)
    assert l3["rc"] == 0 and l3["body"] == st["nonce"], f"L3 did not recover: {l3!r}"
    hits3 = int(_server_view(ssm, st, ctx=ctx)["hits"])
    assert hits3 > int(after2["hits"]), (
        f"L3's request must reach the server and be logged: {after2['hits']!r} -> {hits3!r}")

    # --- L4a: rule ORDER, not specificity ------------------------------------
    ec2.create_network_acl_entry(
        NetworkAclId=acl_server, RuleNumber=90, Protocol="6", RuleAction="deny", Egress=False,
        CidrBlock=_CLIENT_CIDR, PortRange={"From": _PORT, "To": _PORT})
    l4a, base4a, after4a = _blocked_leg(
        ssm, st, what="L4a with an ingress deny at rule 90 above the allow at 100", ctx=ctx)
    assert l4a["body"] == "", f"L4a returned a body, so something answered: {l4a!r}"
    assert int(after4a["hits"]) == int(base4a["hits"]), (
        f"an ingress deny means the request never arrives, so the server logs nothing new; one "
        f"further blocked attempt moved the log {base4a['hits']!r} -> {after4a['hits']!r}")

    # --- L4b: an allow at a LOWER number wins --------------------------------
    ec2.create_network_acl_entry(
        NetworkAclId=acl_server, RuleNumber=80, Protocol="6", RuleAction="allow", Egress=False,
        CidrBlock=_CLIENT_CIDR, PortRange={"From": _PORT, "To": _PORT})
    still_denied = _acl_entry(ec2, acl_server, 90, egress=False)
    assert still_denied["RuleAction"] == "deny", (
        f"the deny at 90 must still be in place, or L4b proves nothing about ordering: "
        f"{still_denied!r}")
    l4b = _reach(ssm, st, expect_ok=True,
                 what="L4b with an identical allow added at rule 80, the deny at 90 still present",
                 ctx=ctx)
    assert l4b["rc"] == 0 and l4b["body"] == st["nonce"], (
        f"NACL entries are first-match-wins by RULE NUMBER, so an identical allow at 80 must beat "
        f"the deny at 90: {l4b!r}")
    hits4b = int(_server_view(ssm, st, ctx=ctx)["hits"])
    assert hits4b > int(after4a["hits"]), (
        f"L4b's request must reach the server and be logged: {after4a['hits']!r} -> {hits4b!r}")

    # --- L5: the stateful contrast -------------------------------------------
    ec2.delete_network_acl_entry(NetworkAclId=acl_server, RuleNumber=80, Egress=False)
    ec2.delete_network_acl_entry(NetworkAclId=acl_server, RuleNumber=90, Egress=False)
    ec2.revoke_security_group_egress(
        GroupId=st["sg_server"],
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.authorize_security_group_egress(
        GroupId=st["sg_server"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": _ENDPOINT_CIDR}]}])
    egress = ec2.describe_security_groups(
        GroupIds=[st["sg_server"]])["SecurityGroups"][0]["IpPermissionsEgress"]
    assert len(egress) == 1, (
        f"the server's security group must hold exactly one egress rule after the narrowing; it "
        f"holds {egress!r}")
    only = egress[0]
    assert (only["IpProtocol"], only["FromPort"], only["ToPort"]) == ("tcp", 443, 443), (
        f"the one remaining egress rule must be tcp/443; it is {only!r}")
    assert [r["CidrIp"] for r in only["IpRanges"]] == [_ENDPOINT_CIDR], (
        f"the one remaining egress rule must reach only the endpoint subnet, so nothing it permits "
        f"could carry the HTTP response back to {_CLIENT_CIDR}; it reaches {only!r}")
    assert only["UserIdGroupPairs"] == [] and only["PrefixListIds"] == [], (
        f"the remaining egress rule must not reach the client by group or prefix list either: "
        f"{only!r}")
    l5 = _reach(ssm, st, expect_ok=True,
                what="L5 with the server's SG egress narrowed to tcp/443 to the endpoint subnet",
                ctx=ctx)
    assert l5["rc"] == 0 and l5["code"] == "200" and l5["body"] == st["nonce"], (
        f"a security group is STATEFUL: the response to a permitted inbound connection must leave "
        f"even though no egress rule covers it. Under the same logical policy a NACL blocked the "
        f"identical flow in L2 (curl {_CURL_TIMEOUT}); here it must succeed. Got {l5!r}")
    after_l5 = _server_view(ssm, st, ctx=ctx)
    assert int(after_l5["hits"]) > hits4b, (
        f"L5's request must appear in the server's own access log: {hits4b!r} -> "
        f"{after_l5['hits']!r}")

    # --- L6: restore, and close the bracket ----------------------------------
    ec2.authorize_security_group_egress(
        GroupId=st["sg_server"],
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    l6 = _reach(ssm, st, expect_ok=True, what="L6 after the server's egress was restored", ctx=ctx)
    assert l6["rc"] == 0 and l6["body"] == st["nonce"], f"L6 did not recover: {l6!r}"


# ===== in-band teardown =====================================================
def _teardown(ec2, iam, st, *, ctx) -> list:
    """Ordered teardown with the waits registered cleanups cannot afford. Runs every step, then
    raises what it could not remove, naming any failure in flight so it is not masked."""
    left = []
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    def _vpc_gone(vpc_id):
        still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
        raise AssertionError(f"vpc {vpc_id} is still describable: {still!r}")

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i))
    if st.get("iface"):
        _step("endpoints", lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=st["iface"]))
        _step("endpoints-deleted", lambda: _poll(
            lambda: [e for e in st["iface"]
                     if _endpoint_state(ec2, e) not in ("deleted", "gone")],
            lambda pending: pending == [], timeout_s=600, interval_s=2,
            what="the interface endpoints reporting deleted", capped=False, ctx=ctx))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=420, interval_s=2,
            what=f"every ENI in {st['vpc']!r} draining", capped=False, ctx=ctx))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    # custom NACLs must be un-associated before they can be deleted
    for assoc_id, default_acl in st.get("restore_assoc", []):
        _step(f"acl-restore {assoc_id}", lambda a=assoc_id, d=default_acl:
              ec2.replace_network_acl_association(AssociationId=a, NetworkAclId=d))
    for acl in st.get("acls", []):
        _step(f"acl {acl}", lambda a=acl: _retry_dependency(
            lambda: ec2.delete_network_acl(NetworkAclId=a)))
    # REVERSED deliberately: the endpoint group's ingress rule names the instance group in
    # `UserIdGroupPairs`, and a security group referenced by another group's rule cannot be
    # deleted (DependencyViolation).
    for sg in reversed(st.get("sgs", [])):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
        _step("vpc-gone", lambda: _vpc_gone(st["vpc"]))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 — collected, raised after every step
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")
    return left


# ===== helpers =====================================
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidVpcEndpointId.NotFound", "InvalidNetworkAclID.NotFound",
               "InvalidAssociationID.NotFound", "InvalidNetworkAclEntry.NotFound")


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
            {"Key": "sim2real", "Value": "b1-nacl-stateless"},
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


def _retry_dependency(fn, timeout_s=240, interval_s=2):
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


def _create_subnet(ctx, ec2, st, cidr, zone, tag_name):
    subnet_id = ec2.create_subnet(
        VpcId=st["vpc"], CidrBlock=cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))
    return subnet_id


def _create_sg(ctx, ec2, st, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_security_group(GroupId=sg), "InvalidGroup.NotFound"))
    return sg


def _attach_permissive_acl(ctx, ec2, st, subnet_id, tag_name):
    """A custom NACL that starts allow-all in both directions, put in place of the subnet's
    default association so the legs can mutate it without touching any other subnet."""
    acl_id = ec2.create_network_acl(
        VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "network-acl", "Tags": _tags_for(tag_name)}],
    )["NetworkAcl"]["NetworkAclId"]
    st["acls"].append(acl_id)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_network_acl(NetworkAclId=acl_id), "InvalidNetworkAclID.NotFound"))
    for egress in (False, True):
        ec2.create_network_acl_entry(
            NetworkAclId=acl_id, RuleNumber=100, Protocol="-1", RuleAction="allow",
            Egress=egress, CidrBlock="0.0.0.0/0")
    current, default_acl = _subnet_acl_association(ec2, st["vpc"], subnet_id)
    new_assoc = ec2.replace_network_acl_association(
        AssociationId=current, NetworkAclId=acl_id)["NewAssociationId"]
    st["restore_assoc"].append((new_assoc, default_acl))
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.replace_network_acl_association(
            AssociationId=new_assoc, NetworkAclId=default_acl),
        "InvalidAssociationID.NotFound", "InvalidNetworkAclID.NotFound"))
    return acl_id


def _subnet_acl_association(ec2, vpc_id, subnet_id):
    default_acl = None
    assoc = None
    for acl in ec2.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]:
        if acl.get("IsDefault"):
            default_acl = acl["NetworkAclId"]
        for a in acl.get("Associations", []):
            if a.get("SubnetId") == subnet_id:
                assoc = a["NetworkAclAssociationId"]
    assert assoc and default_acl, (
        f"could not find the current NACL association for {subnet_id!r} in {vpc_id!r}")
    return assoc, default_acl


def _acl_entry(ec2, acl_id, rule_number, egress):
    acl = ec2.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]
    matches = [e for e in acl["Entries"]
               if e["RuleNumber"] == rule_number and e["Egress"] is egress]
    assert len(matches) == 1, (
        f"expected exactly one {'egress' if egress else 'ingress'} entry numbered "
        f"{rule_number} on {acl_id!r}; the ACL holds {acl['Entries']!r}")
    return matches[0]


def _endpoint_state(ec2, endpoint_id):
    try:
        eps = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidVpcEndpointId.NotFound":
            return "gone"
        raise
    return eps[0]["State"] if eps else "gone"


def _vpc_enis(ec2, vpc_id):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]]


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real b1 nacl statelessness",
                    Tags=[{"Key": "sim2real", "Value": "b1-nacl-stateless"}])
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY),
        "NoSuchEntity"))
    iam.create_instance_profile(
        InstanceProfileName=role_name,
        Tags=[{"Key": "sim2real", "Value": "b1-nacl-stateless"}])
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name), "NoSuchEntity"))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name),
        "NoSuchEntity"))
    # IAM exposes no "role is usable" condition to poll; _launch retries InvalidParameterValue.


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
    nic = {"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
           "AssociatePublicIpAddress": False}
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


def _run_phase(ssm, instance_id, script, timeout_s=300, *, ctx):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real b1 nacl leg"))
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


def _stdout(inv):
    assert inv["ResponseCode"] == 0, (
        f"the control command itself failed on the host: rc={inv['ResponseCode']!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return inv["StandardOutputContent"].strip()


def _json_line(inv):
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the guest reported no stdout: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    return json.loads(lines[-1])


def _client_script():
    # /tmp/body is removed first: curl only truncates its output file once bytes arrive, so a leg
    # that times out would otherwise report the PREVIOUS leg's body and read as reachable.
    return f"""set -uo pipefail
rm -f /tmp/body
CODE=$(curl -s -m 3 -o /tmp/body -w '%{{http_code}}' http://{_SERVER_IP}:{_PORT}/nonce)
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


def _server_script(client_ip):
    return f"""set -uo pipefail
LOCAL=$(curl -s -m 5 http://127.0.0.1:{_PORT}/nonce || true)
HITS=$(grep -c '{client_ip}' /tmp/httpd.log || true)
export LOCAL HITS
python3 - <<'JEOF'
import json, os
print(json.dumps({{"local": os.environ.get("LOCAL", ""),
                  "hits": os.environ.get("HITS", "") or "0"}}))
JEOF
"""


def _server_view(ssm, st, *, ctx):
    return _json_line(_run_phase(ssm, st["server"], _server_script(st["client_ip"]), ctx=ctx))


def _blocked_leg(ssm, st, what, *, ctx):
    """Converge to blocked, then prove ONE more identical attempt leaves the server's access log
    untouched. The baseline is taken after convergence because attempts made before the rule took
    effect do reach the server and get logged."""
    first = _reach(ssm, st, expect_ok=False, what=what, ctx=ctx)
    assert first["rc"] == _CURL_TIMEOUT, (
        f"a DROPPED packet must time the client out (curl {_CURL_TIMEOUT}), not be refused "
        f"(curl 7): {first!r} for {what}")
    base = _server_view(ssm, st, ctx=ctx)
    again = _json_line(_run_phase(ssm, st["client"], _client_script(), ctx=ctx))
    assert again["rc"] == _CURL_TIMEOUT, (
        f"a second identical attempt must be blocked too, or the block was a transient: "
        f"{again!r} for {what}")
    assert again["body"] == "", f"the repeat attempt returned a body: {again!r} for {what}"
    return again, base, _server_view(ssm, st, ctx=ctx)


def _reach(ssm, st, expect_ok, what, *, ctx):
    """Drive one leg from the client and poll until the expected outcome, so a NACL or
    security-group change that has not converged yet is a retry and a change that never converges
    is a FAIL naming what was last seen."""
    return _poll(lambda: _json_line(_run_phase(ssm, st["client"], _client_script(), ctx=ctx)),
                 lambda r: (r["rc"] == 0) is expect_ok,
                 timeout_s=300, interval_s=1.0, what=what, ctx=ctx)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
