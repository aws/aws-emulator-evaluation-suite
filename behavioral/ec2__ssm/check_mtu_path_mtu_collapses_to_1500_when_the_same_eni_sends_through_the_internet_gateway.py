"""mtu-path-mtu-collapses-to-1500-when-the-same-eni-sends-through-the-internet-gateway."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mtu-path-mtu-collapses-to-1500-when-the-same-eni-sends-through-the-internet-gateway"
GROUP = "data-plane"
SERVICES = ["ec2", "ssm"]

_VPC_CIDR = "10.85.0.0/16"
_HOST_CIDR = "10.85.1.0/24"
_INSTANCE_TYPE = "m5.large"
#: The two numbers under test. Both are literals on purpose -- they ARE the contract. Every
#: payload size below is derived from one of them plus what the guest reported.
_VPC_MTU = 9001
_IGW_MTU = 1500
#: 20-byte IPv4 header + 8-byte ICMP echo header. `ping -s` sizes the PAYLOAD.
_IP_ICMP_OVERHEAD = 28
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
               "InvalidAssociationID.NotFound", "Gateway.NotAttached")
_SCENARIO = "mtu-igw-path-1500"


def _on_cleanup(ctx, fn):
    """Register `fn` as the failure-path net. The in-band teardown usually removed the resource
    first, so the operation's documented not-found answer means gone; anything else raises."""
    def _run():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise
    ctx.on_cleanup(_run)


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """From one ENI, an 8973-byte DF ping reaches the peer's private address and 1472 bytes reach
    its public address, but 1473 or 8973 DF bytes to the public address get no reply (both arrive
    with DF cleared), and the route cache then holds mtu 1500 for the public address only."""
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
    r = _mtu_legs(ssm, st["a"], st["b_priv"], st["b_pub"])
    mtu = r["mtu"]
    assert mtu == _VPC_MTU, (
        f"the sending ENI must be handed a {_VPC_MTU}-byte MTU, or neither half of this check is "
        f"interpretable; the guest reports {mtu!r} on {r['dev']!r}")
    assert (r["priv"], r["pub"]) == (st["b_priv"], st["b_pub"]), (
        f"the guest addressed {r['priv']!r}/{r['pub']!r}, not the peer's "
        f"{st['b_priv']!r}/{st['b_pub']!r}")

    big = mtu - _IP_ICMP_OVERHEAD
    small = _IGW_MTU - _IP_ICMP_OVERHEAD
    assert r["sizes"] == {"p1": big, "p2": small, "n1": small + 1, "n2": big,
                          "c1": small + 1, "c2": big}, (
        f"the guest did not size the legs off the MTUs under test ({mtu!r}, {_IGW_MTU!r}): "
        f"{r['sizes']!r}")

    p1 = r["legs"]["p1"]
    assert (p1["rc"], p1["rx"]) == (0, p1["tx"]) and p1["tx"] > 0, (
        f"P1: {big} bytes unfragmented must cross the VPC-local path to {st['b_priv']!r}, or the "
        f"contrast this check is built on does not exist; ping reported {p1!r}")

    p2 = r["legs"]["p2"]
    assert (p2["rc"], p2["rx"]) == (0, p2["tx"]) and p2["tx"] > 0, (
        f"P2: the path through the internet gateway to {st['b_pub']!r} must work at "
        f"{small} = {_IGW_MTU} - {_IP_ICMP_OVERHEAD} bytes, otherwise the negatives below would "
        f"only show that the path is broken; ping reported {p2!r}")

    n1 = r["legs"]["n1"]
    assert n1["rx"] == 0 and n1["tx"] > 0, (
        f"N1: one byte past the {_IGW_MTU}-byte gateway MTU ({small + 1}) must be dropped in "
        f"flight -- the guest's own MTU is {mtu}, so it emitted the frame and the gateway "
        f"discarded it; ping reported {n1!r}")

    n2 = r["legs"]["n2"]
    assert n2["rx"] == 0 and n2["tx"] > 0, (
        f"N2: the SAME {big} bytes that crossed to {st['b_priv']!r} in P1 must NOT reach "
        f"{st['b_pub']!r}; the only difference between the two legs is that this one leaves the "
        f"VPC through the internet gateway. ping reported {n2!r}")

    c1 = r["legs"]["c1"]
    assert (c1["rc"], c1["rx"]) == (0, c1["tx"]) and c1["tx"] > 0, (
        f"C1: {small + 1} bytes must reach {st['b_pub']!r} once the kernel may fragment, which is "
        f"what makes N1 a statement about the {_IGW_MTU}-byte MTU and not about the security "
        f"group or the route; ping reported {c1!r}")

    c2 = r["legs"]["c2"]
    assert (c2["rc"], c2["rx"]) == (0, c2["tx"]) and c2["tx"] > 0, (
        f"C2: {big} bytes must reach {st['b_pub']!r} once the kernel may fragment, which is what "
        f"makes N2 a statement about the gateway's MTU; ping reported {c2!r}")

    # --- the transition: path-MTU discovery actually happened -----------------
    assert r["route_before"]["pub"] is None and r["route_before"]["priv"] is None, (
        f"the guest must start with no MTU override cached for either address, or the 'after' read "
        f"below is not a transition; it started at {r['route_before']!r}")
    assert r["route_after"]["pub"] == _IGW_MTU, (
        f"after the oversized DF probes the guest's route cache must hold mtu {_IGW_MTU} for "
        f"{st['b_pub']!r}: that is path-MTU discovery, and it only works because the internet "
        f"gateway answered with ICMP fragmentation-needed instead of blackholing. The cache holds "
        f"{r['route_after']!r}; the raw lines were {r['route_raw']!r}")
    assert r["route_after"]["priv"] is None, (
        f"the VPC-local path to {st['b_priv']!r} must acquire NO override -- its MTU is the link's "
        f"{mtu} and nothing in the path is smaller; the cache holds {r['route_after']!r}")


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-mtuigw-")
    st["name"] = name
    zone = _usable_zones(ec2, 1)[0]

    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    st["vpc"] = vpc
    _on_cleanup(ctx, lambda: ec2.delete_vpc(VpcId=vpc))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags_for(name)}
    ])["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw
    _on_cleanup(ctx, lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    _on_cleanup(ctx, lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))

    # ONE subnet: both instances share the zone and the broadcast domain, so the only thing that
    # distinguishes the two paths under test is which address is dialled.
    sub = _create_subnet(ctx, ec2, st, _HOST_CIDR, zone, name + "-hosts")

    rtb = ec2.create_route_table(VpcId=vpc, TagSpecifications=[
        {"ResourceType": "route-table", "Tags": _tags_for(name)}])["RouteTable"]["RouteTableId"]
    st["rtbs"].append(rtb)
    _on_cleanup(ctx, lambda: ec2.delete_route_table(RouteTableId=rtb))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=sub)["AssociationId"]
    st["rtb_assoc"].append(assoc)
    _on_cleanup(ctx, lambda: ec2.disassociate_route_table(AssociationId=assoc))

    sg = _create_sg(ctx, ec2, st, name + "-hosts", "sim2real mtu igw path hosts")
    st["sg"] = sg
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1,
         "IpRanges": [{"CidrIp": _VPC_CIDR}]}])

    role = name + "-role"
    st["role"] = st["profile"] = role
    _create_instance_role(ctx, iam, role)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    st["a"] = _launch(ctx, ec2, st, ami, sub, sg, name + "-a")
    st["b"] = _launch(ctx, ec2, st, ami, sub, sg, name + "-b")

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[st["a"], st["b"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    by_id = _describe(ec2, [st["a"], st["b"]])
    for k in ("a", "b"):
        st[k + "_priv"] = by_id[st[k]]["PrivateIpAddress"]
        st[k + "_pub"] = by_id[st[k]].get("PublicIpAddress")
        st[k + "_az"] = by_id[st[k]]["Placement"]["AvailabilityZone"]
        assert by_id[st[k]]["InstanceType"] == _INSTANCE_TYPE, (
            f"instance {k} came up as {by_id[st[k]]['InstanceType']!r}, not {_INSTANCE_TYPE!r}")
        assert st[k + "_pub"], (
            f"instance {k} ({st[k]!r}) has no public IPv4 address, so there is no internet-gateway "
            f"path to grade: {by_id[st[k]]!r}")
    assert st["a_az"] == st["b_az"], (
        f"both instances must share one zone so that distance cannot explain the difference; they "
        f"are in {st['a_az']!r} and {st['b_az']!r}")

    # Reaching the peer by its PUBLIC address hairpins through the gateway, so the packets arrive
    # with the sender's PUBLIC source address. Authorised per /32 from the addresses AWS just
    # assigned to these two instances -- never 0.0.0.0/0, and never a pre-existing rule.
    for k in ("a", "b"):
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1,
             "IpRanges": [{"CidrIp": st[k + "_pub"] + "/32",
                           "Description": "sim2real igw hairpin from " + st[k]}]}])

    for k in ("a", "b"):
        _poll(lambda i=st[k]: _agent_view(ssm, i),
              lambda i: i is not None and i.get("PingStatus") == "Online",
              timeout_s=600, interval_s=10,
              what=f"the SSM agent on instance {k} ({st[k]}) coming Online")


# ===== the guest-side acts ==================================================
def _mtu_legs(ssm, instance_id, priv, pub):
    """One guest-side pass: read the cache, run six legs, read the cache again.

    A single invocation on purpose -- the 'before' and 'after' route-cache reads must bracket the
    oversized probes with nothing in between, and the cache entry expires on its own (measured
    ~600 s), so splitting them across two SSM round trips would make the transition unobservable.
    """
    script = """set -uo pipefail
python3 - <<'PYEOF'
import json, os, pathlib, re, subprocess

priv, pub = os.environ["SIM2REAL_PRIV"], os.environ["SIM2REAL_PUB"]
dev = subprocess.run(["sh", "-c", "ip -o -4 route show default | awk '{print $5}'"],
                     capture_output=True, text=True).stdout.strip()
mtu = int(pathlib.Path("/sys/class/net/%s/mtu" % dev).read_text().strip())
raw = {}


def route(dst, label):
    p = subprocess.run(["ip", "route", "get", dst], capture_output=True, text=True)
    raw[label] = (p.stdout + p.stderr).strip()[-240:]
    m = re.search(r"\\bmtu (\\d+)\\b", p.stdout)
    return int(m.group(1)) if m else None


def ping(df, size, dst):
    p = subprocess.run(["ping", "-M", "do" if df else "dont", "-n", "-c", "3", "-W", "5",
                        "-s", str(size), dst], capture_output=True, text=True)
    m = re.search(r"(\\d+) packets transmitted, (\\d+) received", p.stdout)
    return {"rc": p.returncode, "size": size, "df": df, "dst": dst,
            "tx": int(m.group(1)) if m else -1, "rx": int(m.group(2)) if m else -1,
            "tail": (p.stdout + p.stderr).strip()[-240:]}


before = {"pub": route(pub, "before_pub"), "priv": route(priv, "before_priv")}
big, small = mtu - 28, 1500 - 28
legs = {
    "p1": ping(True, big, priv),
    "p2": ping(True, small, pub),
    "n1": ping(True, small + 1, pub),
    "n2": ping(True, big, pub),
    "c1": ping(False, small + 1, pub),
    "c2": ping(False, big, pub),
}
after = {"pub": route(pub, "after_pub"), "priv": route(priv, "after_priv")}
print("SIM2REAL_JSON " + json.dumps(
    {"dev": dev, "mtu": mtu, "priv": priv, "pub": pub,
     "sizes": {k: v["size"] for k, v in legs.items()},
     "legs": legs, "route_before": before, "route_after": after, "route_raw": raw}))
PYEOF
"""
    return _json_marker(_run_phase(
        ssm, instance_id,
        f"export SIM2REAL_PRIV={priv}\nexport SIM2REAL_PUB={pub}\n" + script, timeout_s=600))


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
    _on_cleanup(ctx, lambda: ec2.delete_subnet(SubnetId=sub))
    return sub


def _create_sg(ctx, ec2, st, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    _on_cleanup(ctx, lambda: ec2.delete_security_group(GroupId=sg))
    return sg


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real " + _SCENARIO,
                    Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    _on_cleanup(ctx, lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    _on_cleanup(ctx, lambda: iam.detach_role_policy(RoleName=role_name,
                                                    PolicyArn=_SSM_CORE_POLICY))
    iam.create_instance_profile(InstanceProfileName=role_name,
                               Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    _on_cleanup(ctx, lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    _on_cleanup(ctx, lambda: iam.remove_role_from_instance_profile(
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
        # Tagged in the SAME call, for both the instance and its volume: tag-based cleanup finds
        # EC2 instances by tag only, so an untagged instance is invisible to it forever and
        # bills silently. A follow-up tag call is a call an abort can skip.
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume")],
    )
    iid = _call_with_retry(lambda: ec2.run_instances(**kwargs),
                           codes=_THROTTLE + ("InvalidParameterValue",),
                           retries=30, delay=5.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    # Registered BEFORE any readiness poll: a host that never registers must not strand billing.
    _on_cleanup(ctx, lambda: ec2.terminate_instances(InstanceIds=[iid]))
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
    for attempt in range(25):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DeleteConflict" and attempt < 24:
                time.sleep(2)
                continue
            raise


def _teardown(ec2, iam, st) -> None:
    """Ordered teardown with the waits `ctx.on_cleanup`'s 60 s budget cannot afford. Runs every
    step, then raises what it could not remove, carrying any failure in flight."""
    found = sys.exc_info()[1]
    left = []
    steps = []

    def _step(label, fn):
        steps.append((label, fn))

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
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 - collected, raised after the last step
            left.append(f"{label}: {exc!r}")
    if st.get("vpc"):
        try:
            still = ec2.describe_vpcs(VpcIds=[st["vpc"]])["Vpcs"]
            left.append(f"vpc {st['vpc']} is still describable: {still!r}")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidVpcID.NotFound":
                left.append(f"vpc {st['vpc']} describe returned {code!r}")
                raise RuntimeError(_leftover_message(found, left)) from exc
    if left:
        raise AssertionError(_leftover_message(found, left))


def _leftover_message(found, left) -> str:
    """The teardown failure, prefixed with the failure in flight when there is one."""
    return ((f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
