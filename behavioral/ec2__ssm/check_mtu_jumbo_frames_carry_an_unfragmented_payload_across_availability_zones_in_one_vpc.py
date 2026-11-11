"""mtu-jumbo-frames-carry-an-unfragmented-payload-across-availability-zones-in-one-vpc."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mtu-jumbo-frames-carry-an-unfragmented-payload-across-availability-zones-in-one-vpc"
GROUP = "data-plane"
SERVICES = ["ec2", "ssm"]

_VPC_CIDR = "10.84.0.0/16"
_A_CIDR = "10.84.1.0/24"
_B_CIDR = "10.84.2.0/24"
#: m5.large: a current-generation ENA instance, the
#: smallest m5 size, and jumbo frames are a property of the ENA path rather than of the size.
_INSTANCE_TYPE = "m5.large"
#: The AWS-documented VPC MTU. This is the number under test, so it is a literal on purpose --
#: every OTHER size below is derived from what the guest actually reports.
_VPC_MTU = 9001
#: 20-byte IPv4 header + 8-byte ICMP echo header. `ping -s` sizes the PAYLOAD.
_IP_ICMP_OVERHEAD = 28
#: The commonly quoted jumbo payload (9000 - 28), kept as its own leg.
_BRIEF_PAYLOAD = 8972
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
               "InvalidAssociationID.NotFound", "Gateway.NotAttached")

_SCENARIO = "mtu-jumbo-intra-vpc"


def _gone_ok(fn):
    """A cleanup step that tolerates the resource being gone already: the ordered teardown in the
    `finally` deletes the same resources first, so this second net finds most of them absent."""

    def step():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise

    return step


@tags("cap:c3", "concern:data-plane", "concern:e2e", "dp:native", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """Two m5.large in one VPC but different AZs report a 9001-byte MTU and exchange an 8973-byte
    DF-set ICMP echo (MTU - 28); one byte more with DF set is lost, and the same size crosses once
    the kernel may fragment it, so a jumbo frame crosses the AZ boundary intact."""
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
    # Both guests report their own interface MTU: the claim is about the VPC, not about one host.
    peer = _guest_facts(ssm, st["b"])
    assert peer["mtu"] == _VPC_MTU, (
        f"the peer instance {st['b']!r} in {st['b_az']!r} reports MTU {peer['mtu']!r} on "
        f"{peer['dev']!r}; a VPC ENI must be handed {_VPC_MTU}")

    probe = _mtu_legs(ssm, st["a"], st["b_priv"])
    mtu = probe["mtu"]
    assert mtu == _VPC_MTU, (
        f"the sending instance {st['a']!r} in {st['a_az']!r} reports MTU {mtu!r} on "
        f"{probe['dev']!r}; a VPC ENI must be handed {_VPC_MTU}")
    assert probe["dst"] == st["b_priv"], (
        f"the guest pinged {probe['dst']!r}, not the peer's private address {st['b_priv']!r}")

    max_df = mtu - _IP_ICMP_OVERHEAD
    assert probe["sizes"] == [_BRIEF_PAYLOAD, max_df, max_df + 1, max_df + 1], (
        f"the guest did not size the four legs off its own MTU {mtu!r}: {probe['sizes']!r}")

    l1 = probe["legs"]["df_brief"]
    assert (l1["rc"], l1["rx"]) == (0, l1["tx"]) and l1["tx"] > 0, (
        f"an {_BRIEF_PAYLOAD}-byte ICMP payload with DF set must cross the VPC from "
        f"{st['a_az']!r} to {st['b_az']!r} intact; ping reported {l1!r}")

    l2 = probe["legs"]["df_max"]
    assert (l2["rc"], l2["rx"]) == (0, l2["tx"]) and l2["tx"] > 0, (
        f"the largest payload that fits in a {mtu}-byte frame unfragmented is "
        f"{max_df} = {mtu} - {_IP_ICMP_OVERHEAD}, and it must cross {st['a_az']!r} -> "
        f"{st['b_az']!r} intact; ping reported {l2!r}")

    l3 = probe["legs"]["df_over"]
    assert l3["rx"] == 0 and l3["tx"] > 0, (
        f"{max_df + 1} bytes cannot fit in a {mtu}-byte frame, so with DF set NOTHING may come "
        f"back -- the guest's own stack must refuse to emit it; ping reported {l3!r}")
    assert l3["rc"] != 0, (
        f"ping must report failure when every oversized DF packet is lost: {l3!r}")

    l4 = probe["legs"]["frag_over"]
    assert (l4["rc"], l4["rx"]) == (0, l4["tx"]) and l4["tx"] > 0, (
        f"the same {max_df + 1} bytes must cross the same path once the kernel may fragment, "
        f"which is what makes the DF loss above evidence about the {mtu}-byte MTU rather than "
        f"about reachability; ping reported {l4!r}")


# ===== the fixture ==========================================================
def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-mtujaz-")
    st["name"] = name
    zones = _usable_zones(ec2, 2)

    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    st["vpc"] = vpc
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_vpc(VpcId=vpc)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    # The instances reach SSM over the internet gateway rather than through interface endpoints:
    # the control channel is only the instrument here, and three endpoint ENIs would add several
    # minutes of create and drain to a check whose subject is two datagram sizes. The jumbo path
    # under test is the VPC-local one, which the gateway does not touch.
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags_for(name)}
    ])["InternetGateway"]["InternetGatewayId"]
    st["igw"] = igw
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(_gone_ok(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))

    sub_a = _create_subnet(ctx, ec2, st, _A_CIDR, zones[0], name + "-a")
    sub_b = _create_subnet(ctx, ec2, st, _B_CIDR, zones[1], name + "-b")

    rtb = ec2.create_route_table(VpcId=vpc, TagSpecifications=[
        {"ResourceType": "route-table", "Tags": _tags_for(name)}])["RouteTable"]["RouteTableId"]
    st["rtbs"].append(rtb)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_route_table(RouteTableId=rtb)))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    for sub in (sub_a, sub_b):
        assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=sub)["AssociationId"]
        st["rtb_assoc"].append(assoc)
        ctx.on_cleanup(_gone_ok(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))

    # ICMP is permitted only from inside this VPC's own CIDR, so the legs below are VPC-local by
    # construction and nothing on the internet can answer them.
    sg = _create_sg(ctx, ec2, st, name + "-hosts", "sim2real mtu jumbo intra-vpc hosts")
    st["sg"] = sg
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1,
         "IpRanges": [{"CidrIp": _VPC_CIDR}]}])

    role = name + "-role"
    st["role"] = st["profile"] = role
    _create_instance_role(ctx, iam, role)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    st["a"] = _launch(ctx, ec2, st, ami, sub_a, sg, name + "-a")
    st["b"] = _launch(ctx, ec2, st, ami, sub_b, sg, name + "-b")

    ec2.get_waiter("instance_running").wait(InstanceIds=[st["a"], st["b"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    by_id = _describe(ec2, [st["a"], st["b"]])
    for k in ("a", "b"):
        st[k + "_priv"] = by_id[st[k]]["PrivateIpAddress"]
        st[k + "_az"] = by_id[st[k]]["Placement"]["AvailabilityZone"]
        assert by_id[st[k]]["InstanceType"] == _INSTANCE_TYPE, (
            f"instance {k} came up as {by_id[st[k]]['InstanceType']!r}, not {_INSTANCE_TYPE!r}, "
            f"so the jumbo path under test is not the one this check claims to grade")
    assert st["a_az"] != st["b_az"], (
        f"both instances landed in {st['a_az']!r}; this check exists to cross an AZ boundary "
        f"inside one VPC and proves nothing if they share a zone")

    for k in ("a", "b"):
        _poll(lambda i=st[k]: _agent_view(ssm, i),
              lambda i: i is not None and i.get("PingStatus") == "Online",
              timeout_s=600, interval_s=2,
              what=f"the SSM agent on instance {k} ({st[k]}) coming Online")


# ===== the guest-side acts ==================================================
def _mtu_legs(ssm, instance_id, dst):
    """Read the interface MTU inside the guest, then run the four legs sized off THAT number."""
    script = """set -uo pipefail
python3 - <<'PYEOF'
import json, pathlib, re, subprocess, os
dst = os.environ["SIM2REAL_DST"]
dev = subprocess.run(["sh", "-c", "ip -o -4 route show default | awk '{print $5}'"],
                     capture_output=True, text=True).stdout.strip()
mtu = int(pathlib.Path("/sys/class/net/%s/mtu" % dev).read_text().strip())


def ping(df, size):
    p = subprocess.run(["ping", "-M", "do" if df else "dont", "-n", "-c", "3", "-W", "5",
                        "-s", str(size), dst], capture_output=True, text=True)
    m = re.search(r"(\\d+) packets transmitted, (\\d+) received", p.stdout)
    return {"rc": p.returncode, "size": size, "df": df,
            "tx": int(m.group(1)) if m else -1, "rx": int(m.group(2)) if m else -1,
            "tail": (p.stdout + p.stderr).strip()[-240:]}


max_df = mtu - 28
legs = {"df_brief": ping(True, 8972), "df_max": ping(True, max_df),
        "df_over": ping(True, max_df + 1), "frag_over": ping(False, max_df + 1)}
print("SIM2REAL_JSON " + json.dumps(
    {"dev": dev, "mtu": mtu, "dst": dst,
     "sizes": [legs[k]["size"] for k in ("df_brief", "df_max", "df_over", "frag_over")],
     "legs": legs}))
PYEOF
"""
    return _json_marker(_run_phase(ssm, instance_id,
                                   f"export SIM2REAL_DST={dst}\n" + script, timeout_s=420))


def _guest_facts(ssm, instance_id):
    script = """set -uo pipefail
python3 - <<'PYEOF'
import json, pathlib, subprocess
dev = subprocess.run(["sh", "-c", "ip -o -4 route show default | awk '{print $5}'"],
                     capture_output=True, text=True).stdout.strip()
print("SIM2REAL_JSON " + json.dumps(
    {"dev": dev, "mtu": int(pathlib.Path("/sys/class/net/%s/mtu" % dev).read_text().strip())}))
PYEOF
"""
    return _json_marker(_run_phase(ssm, instance_id, script))


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
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_subnet(SubnetId=sub)))
    return sub


def _create_sg(ctx, ec2, st, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=st["vpc"],
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(_gone_ok(lambda: ec2.delete_security_group(GroupId=sg)))
    return sg


def _create_instance_role(ctx, iam, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real " + _SCENARIO,
                    Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(_gone_ok(lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=_SSM_CORE_POLICY)))
    iam.create_instance_profile(InstanceProfileName=role_name,
                               Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    ctx.on_cleanup(_gone_ok(lambda: iam.delete_instance_profile(InstanceProfileName=role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(_gone_ok(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name)))
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
    ctx.on_cleanup(_gone_ok(lambda: ec2.terminate_instances(InstanceIds=[iid])))
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
        Parameters={"commands": [script]}, TimeoutSeconds=600,
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
