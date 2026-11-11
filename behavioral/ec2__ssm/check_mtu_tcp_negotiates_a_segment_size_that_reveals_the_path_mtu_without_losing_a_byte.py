"""mtu-tcp-negotiates-a-segment-size-that-reveals-the-path-mtu-without-losing-a-byte."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mtu-tcp-negotiates-a-segment-size-that-reveals-the-path-mtu-without-losing-a-byte"
GROUP = "data-plane"
SERVICES = ["ec2", "ssm"]

_VPC_CIDR = "10.86.0.0/16"
_HOST_CIDR = "10.86.1.0/24"
_INSTANCE_TYPE = "m5.large"
#: The two MTUs under test. Nothing below hardcodes a segment size: every expectation is
#: DERIVED from these two and from what the guest reported, because the per-segment overhead
#: depends on which TCP options the kernel negotiated and is not ours to predict.
_VPC_MTU = 9001
_IGW_MTU = 1500
_PORT = 9001
#: Enough to force thousands of full-size segments on either path, so a segment size that was
#: only ever going to work for small writes could not survive this.
_BYTES = 4 * 1024 * 1024
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
               "InvalidAssociationID.NotFound", "Gateway.NotAttached")
_SCENARIO = "mtu-tcp-mss"

#: Guest phase 1, on the PEER: a byte-counting TCP sink that reports the source address it saw.
#: The source address is evidence, not bookkeeping -- see the docstring's fourth assertion.
_SINK = r"""
cat > /tmp/sink.py <<'PYEOF'
import json, socket
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", %(port)d))
srv.listen(8)
srv.settimeout(420)
for _ in range(6):
    try:
        conn, peer = srv.accept()
    except Exception:
        break
    conn.settimeout(120)
    total = 0
    while True:
        b = conn.recv(262144)
        if not b:
            break
        total += len(b)
    print("SIM2REAL_SERVED " + json.dumps({"src": peer[0], "total": total}), flush=True)
    try:
        conn.sendall(str(total).encode())
        conn.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    conn.close()
PYEOF
nohup setsid python3 /tmp/sink.py >/tmp/sink.log 2>&1 </dev/null &
sleep 2
ss -ltn | grep -q ':%(port)d ' && echo SIM2REAL_LISTENING || echo SIM2REAL_NOT_LISTENING
"""

#: Guest phase 2, on the SENDER: one connection per destination address, reading the negotiated
#: segment size and the kernel's notion of the path MTU at three points, then streaming the
#: payload and reading back the peer's count.
_CLIENT = r"""
export SIM2REAL_PRIV=%(priv)s
export SIM2REAL_PUB=%(pub)s
python3 - <<'PYEOF'
import json, os, re, socket, subprocess

IP_MTU = 14
priv, pub = os.environ["SIM2REAL_PRIV"], os.environ["SIM2REAL_PUB"]
PORT, N = %(port)d, %(nbytes)d
dev = subprocess.run(["sh", "-c", "ip -o -4 route show default | awk '{print $5}'"],
                     capture_output=True, text=True).stdout.strip()
link_mtu = int(open("/sys/class/net/%%s/mtu" %% dev).read().strip())


def route_mtu(dst):
    p = subprocess.run(["ip", "route", "get", dst], capture_output=True, text=True)
    m = re.search(r"\bmtu (\d+)\b", p.stdout)
    return int(m.group(1)) if m else None


def probe(s):
    return {"ip_mtu": s.getsockopt(socket.IPPROTO_IP, IP_MTU),
            "maxseg": s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)}


def leg(dst):
    out = {"dst": dst, "sent": N, "route_mtu_before": route_mtu(dst)}
    s = socket.create_connection((dst, PORT), timeout=30)
    out["at_connect"] = probe(s)
    s.sendall(b"x" * N)
    out["after_send"] = probe(s)
    s.shutdown(socket.SHUT_WR)
    s.settimeout(120)
    echo = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        echo += b
    out["at_close"] = probe(s)
    s.close()
    out["echo"] = echo.decode(errors="replace")[:64]
    out["route_mtu_after"] = route_mtu(dst)
    return out


res = {"dev": dev, "link_mtu": link_mtu, "legs": {}}
for label, dst in (("priv", priv), ("pub", pub)):
    res["legs"][label] = leg(dst)
print("SIM2REAL_JSON " + json.dumps(res))
PYEOF
"""


@tags("cap:c3", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """A 4 MiB TCP stream arrives whole over both the private (MTU 9001) and the internet-gateway
    (MTU 1500) path to the same peer, its negotiated TCP_MAXSEG differs by exactly 9001 - 1500 while
    IP_MTU reads 9001 on both, and the peer sees the sender's public address on the gateway path."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"subnets": [], "sgs": [], "instances": [], "rtb_assoc": [], "rtbs": []}
    try:
        _build(ctx, ec2, ssm, iam, st)
        _legs(ssm, st)
    finally:
        _teardown(ec2, iam, st)


def _legs(ssm, st) -> None:
    sink = _run_phase(ssm, st["b"], _SINK % {"port": _PORT}, timeout_s=420)
    assert sink["ResponseCode"] == 0, (
        f"starting the sink on the peer failed: rc={sink['ResponseCode']!r} "
        f"stderr={sink.get('StandardErrorContent')!r}")
    assert "SIM2REAL_LISTENING" in sink["StandardOutputContent"], (
        f"the peer is not listening on {_PORT}, so neither leg below would measure the network: "
        f"{sink['StandardOutputContent']!r}")

    r = _json_marker(_run_phase(ssm, st["a"], _CLIENT % {
        "priv": st["b_priv"], "pub": st["b_pub"], "port": _PORT, "nbytes": _BYTES},
        timeout_s=900))
    link = r["link_mtu"]
    assert link == _VPC_MTU, (
        f"the sending ENI must be handed a {_VPC_MTU}-byte MTU, or the {link!r} it reports on "
        f"{r['dev']!r} -- not the gateway -- would explain the segment sizes below")

    priv, pub = r["legs"]["priv"], r["legs"]["pub"]
    assert (priv["dst"], pub["dst"]) == (st["b_priv"], st["b_pub"]), (
        f"the guest dialled {priv['dst']!r}/{pub['dst']!r}, not the peer's "
        f"{st['b_priv']!r}/{st['b_pub']!r}")

    # --- 1. every byte arrives on both paths ---------------------------------
    for label, leg in (("private", priv), ("internet-gateway", pub)):
        assert leg["echo"] == str(leg["sent"]), (
            f"the peer must account for all {leg['sent']} bytes on the {label} path -- TCP is "
            f"supposed to hide the MTU difference, not lose data to it; it echoed "
            f"{leg['echo']!r}")

    # --- 2. the segment size, and only it, carries the path MTU --------------
    for label, leg in (("private", priv), ("internet-gateway", pub)):
        for when in ("at_connect", "after_send", "at_close"):
            assert leg[when]["maxseg"] == leg["at_connect"]["maxseg"], (
                f"the {label} path's segment size changed during the transfer "
                f"({leg['at_connect']['maxseg']!r} at connect, {leg[when]['maxseg']!r} at "
                f"{when}), so it was not settled by the handshake after all: {leg!r}")
    mss_priv = priv["at_connect"]["maxseg"]
    mss_pub = pub["at_connect"]["maxseg"]
    assert mss_priv - mss_pub == _VPC_MTU - _IGW_MTU, (
        f"the two paths' segment sizes must differ by exactly the two MTUs' difference "
        f"({_VPC_MTU} - {_IGW_MTU} = {_VPC_MTU - _IGW_MTU}); they are {mss_priv!r} and "
        f"{mss_pub!r}, a difference of {mss_priv - mss_pub}")
    overhead = _VPC_MTU - mss_priv
    assert 0 < overhead < _IGW_MTU, (
        f"the per-segment overhead recovered from the private leg is {overhead!r}, which cannot be "
        f"a header size; {mss_priv!r} is not a segment size for a {_VPC_MTU}-byte path")
    assert mss_pub == _IGW_MTU - overhead, (
        f"the same {overhead}-byte overhead that explains the private path's {mss_priv} must "
        f"explain the gateway path: {_IGW_MTU} - {overhead} = {_IGW_MTU - overhead}, but the "
        f"socket reports {mss_pub!r}")

    # --- 3. IP_MTU is blind to the gateway; the route cache stays clean ------
    for label, leg in (("private", priv), ("internet-gateway", pub)):
        assert leg["at_connect"]["ip_mtu"] == link, (
            f"IP_MTU on the {label} path must report the local link's {link}, not the path's -- "
            f"it is the option a reader expects to be the path MTU and it is not; the guest read "
            f"{leg['at_connect']['ip_mtu']!r}")
        assert leg["route_mtu_before"] is None and leg["route_mtu_after"] is None, (
            f"the {label} path must acquire NO cached MTU override: TCP negotiated the right "
            f"segment size in the handshake, so nothing was ever oversized and path-MTU discovery "
            f"never ran. The cache holds {leg['route_mtu_before']!r} before and "
            f"{leg['route_mtu_after']!r} after")

    # --- 4. the second connection really did leave the VPC ------------------
    log = _run_phase(ssm, st["b"], "cat /tmp/sink.log", timeout_s=300)
    assert log["ResponseCode"] == 0, (
        f"reading the peer's sink log failed: {log.get('StandardErrorContent')!r}")
    served = [json.loads(ln[len("SIM2REAL_SERVED "):])
              for ln in log["StandardOutputContent"].splitlines()
              if ln.startswith("SIM2REAL_SERVED ")]
    assert len(served) == 2, (
        f"the peer must have served exactly the two connections this check made; its log holds "
        f"{served!r} (raw: {log['StandardOutputContent']!r})")
    assert [s["src"] for s in served] == [st["a_priv"], st["a_pub"]], (
        f"the peer must have seen the private-address connection arrive from the sender's private "
        f"{st['a_priv']!r} and the public-address one from its public {st['a_pub']!r} -- that "
        f"source translation is the proof the second stream actually traversed the internet "
        f"gateway. It saw {[s['src'] for s in served]!r}")
    assert [s["total"] for s in served] == [priv["sent"], pub["sent"]], (
        f"the peer's own byte counts must match what was sent on each leg: {served!r}")


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-mtutcp-")
    st["name"] = name
    zone = _usable_zones(ec2, 1)[0]

    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    st["vpc"] = vpc
    _second_net(ctx, lambda: ec2.delete_vpc(VpcId=vpc))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags_for(name)}
    ])["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw
    _second_net(ctx, lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    _second_net(ctx, lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))

    # ONE subnet: both instances share the zone and the broadcast domain, so the only thing that
    # distinguishes the two streams is which of the peer's addresses is dialled.
    sub = _create_subnet(ctx, ec2, st, _HOST_CIDR, zone, name + "-hosts")

    rtb = ec2.create_route_table(VpcId=vpc, TagSpecifications=[
        {"ResourceType": "route-table", "Tags": _tags_for(name)}])["RouteTable"]["RouteTableId"]
    st["rtbs"].append(rtb)
    _second_net(ctx, lambda: ec2.delete_route_table(RouteTableId=rtb))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=sub)["AssociationId"]
    st["rtb_assoc"].append(assoc)
    _second_net(ctx, lambda: ec2.disassociate_route_table(AssociationId=assoc))

    sg = _create_sg(ctx, ec2, st, name + "-hosts", "sim2real mtu tcp mss hosts")
    st["sg"] = sg
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
         "IpRanges": [{"CidrIp": _VPC_CIDR}]}])

    role = name + "-role"
    st["role"] = st["profile"] = role
    _create_instance_role(ctx, iam, role)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    st["a"] = _launch(ctx, ec2, st, ami, sub, sg, name + "-a")
    st["b"] = _launch(ctx, ec2, st, ami, sub, sg, name + "-b")

    ec2.get_waiter("instance_running").wait(InstanceIds=[st["a"], st["b"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    by_id = _describe(ec2, [st["a"], st["b"]])
    for k in ("a", "b"):
        st[k + "_priv"] = by_id[st[k]]["PrivateIpAddress"]
        st[k + "_pub"] = by_id[st[k]].get("PublicIpAddress")
        st[k + "_az"] = by_id[st[k]]["Placement"]["AvailabilityZone"]
        assert by_id[st[k]]["InstanceType"] == _INSTANCE_TYPE, (
            f"instance {k} came up as {by_id[st[k]]['InstanceType']!r}, not {_INSTANCE_TYPE!r}")
        assert st[k + "_pub"], (
            f"instance {k} ({st[k]!r}) has no public IPv4 address, so there is no "
            f"internet-gateway path to measure: {by_id[st[k]]!r}")
    assert st["a_az"] == st["b_az"], (
        f"both instances must share one zone so that distance cannot explain the difference; they "
        f"are in {st['a_az']!r} and {st['b_az']!r}")

    # Dialling the peer by its PUBLIC address hairpins through the gateway, so the connection
    # arrives with the sender's PUBLIC source address -- which the VPC-CIDR rule above does not
    # admit. Authorised per /32 from the addresses AWS just assigned these two instances; never
    # 0.0.0.0/0, and never a pre-existing rule.
    for k in ("a", "b"):
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
             "IpRanges": [{"CidrIp": st[k + "_pub"] + "/32",
                           "Description": "sim2real igw hairpin from " + st[k]}]}])

    for k in ("a", "b"):
        _poll(lambda i=st[k]: _agent_view(ssm, i),
              lambda i: i is not None and i.get("PingStatus") == "Online",
              timeout_s=600, interval_s=2,
              what=f"the SSM agent on instance {k} ({st[k]}) coming Online")



def _second_net(ctx, fn):
    """Register a non-waiting cleanup net behind the in-band teardown. That teardown has normally
    removed the resource already, so a not-found answer here is the expected outcome."""
    def _quiet():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise
    ctx.on_cleanup(_quiet)

# ===== helpers =====================================
def _tags_for(name):
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": _SCENARIO},
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
    """Intersect the type's own offerings with the zones reporting `available`.

    Both halves are load-bearing: `describe_instance_type_offerings` says nothing about zone
    state, `describe_availability_zones` says nothing about instance types, and a literal zone
    name is a capacity gamble wearing a fixed name because the names are per-account aliases.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= want, (
        f"this region offers {_INSTANCE_TYPE} in available zones {usable!r}, and this check needs "
        f"{want}; a region that cannot place the pair cannot run it")
    return usable[:want]


def _create_subnet(ctx, ec2, st, cidr, zone, tag_name):
    sub = ec2.create_subnet(
        VpcId=st["vpc"], CidrBlock=cidr, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(tag_name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(sub)
    _second_net(ctx, lambda: ec2.delete_subnet(SubnetId=sub))
    return sub


def _create_sg(ctx, ec2, st, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    _second_net(ctx, lambda: ec2.delete_security_group(GroupId=sg))
    return sg


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real " + _SCENARIO,
                    Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    _second_net(ctx, lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    _second_net(ctx, lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=_SSM_CORE_POLICY))
    iam.create_instance_profile(InstanceProfileName=role_name,
                               Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    _second_net(ctx, lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    _second_net(ctx, lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name))
    # IAM exposes no "this role is usable" condition to poll. `_launch`'s bounded retry on
    # InvalidParameterValue is what makes this correct; no sleep stands in for it.


def _launch(ctx, ec2, st, ami, subnet_id, sg_id, tag_name):
    kwargs = dict(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet_id, "Groups": [sg_id],
                            "AssociatePublicIpAddress": True}],
        IamInstanceProfile={"Name": st["profile"]},
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        # Tagged in the SAME call, for both the instance and its volume: a follow-up tag call is a
        # call an abort can skip, leaving an untagged instance nothing can find by tag.
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume")],
    )
    iid = _call_with_retry(lambda: ec2.run_instances(**kwargs),
                           codes=_THROTTLE + ("InvalidParameterValue",),
                           retries=30, delay=5.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    _second_net(ctx, lambda: ec2.terminate_instances(InstanceIds=[iid]))
    return iid


def _describe(ec2, instance_ids):
    # RunInstances is eventually consistent: DescribeInstances can 404 an id it just minted.
    reservations = _call_with_retry(
        lambda: ec2.describe_instances(InstanceIds=instance_ids),
        codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=12, delay=5.0)["Reservations"]
    return {i["InstanceId"]: i for r in reservations for i in r["Instances"]}


def _wait_terminated(ec2, instance_id, timeout_s=420):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [i["State"]["Name"] for i in _describe(ec2, [instance_id]).values()]
        if states and all(s == "terminated" for s in states):
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
        Parameters={"commands": [script]}, TimeoutSeconds=900,
        Comment="sim2real " + _SCENARIO))
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


def _json_marker(inv):
    """The one line the guest agreed to emit, parsed structurally rather than by scraping."""
    assert inv["ResponseCode"] == 0, (
        f"the guest-side command failed: rc={inv['ResponseCode']!r} "
        f"status={inv.get('Status')!r} stderr={inv.get('StandardErrorContent')!r}")
    marked = [ln for ln in inv["StandardOutputContent"].splitlines()
              if ln.startswith("SIM2REAL_JSON ")]
    assert len(marked) == 1, (
        f"expected exactly one SIM2REAL_JSON line from the guest; stdout was "
        f"{inv['StandardOutputContent']!r} stderr {inv.get('StandardErrorContent')!r}")
    return json.loads(marked[0][len("SIM2REAL_JSON "):])


def _vpc_enis(ec2, vpc_id):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]]


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


def _teardown(ec2, iam, st) -> list:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises what it could not remove, naming any failure in flight so it is not masked."""
    left = []
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    def _vpc_gone(vpc_id):
        still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
        raise AssertionError(f"vpc {vpc_id} is still describable: {still!r}")

    # Instances first, and every terminate issued before any wait: one net per instance would make
    # the cost the SUM of the waits instead of the max.
    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_terminated(ec2, i))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda e: e == [],
            timeout_s=420, interval_s=2, what=f"every ENI in {st['vpc']!r} draining"))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    for assoc in st.get("rtb_assoc", []):
        _step(f"rtb-assoc {assoc}", lambda a=assoc: ec2.disassociate_route_table(AssociationId=a))
    for rtb in st.get("rtbs", []):
        _step(f"rtb {rtb}", lambda r=rtb: _retry_dependency(
            lambda: ec2.delete_route_table(RouteTableId=r)))
    if st.get("igw") and st.get("vpc"):
        _step("igw-detach", lambda: _retry_dependency(lambda: ec2.detach_internet_gateway(
            InternetGatewayId=st["igw"], VpcId=st["vpc"])))
        _step("igw", lambda: _retry_dependency(lambda: ec2.delete_internet_gateway(
            InternetGatewayId=st["igw"])))
    for sg in reversed(st.get("sgs", [])):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for sub in st.get("subnets", []):
        _step(f"subnet {sub}", lambda s=sub: _retry_dependency(
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
