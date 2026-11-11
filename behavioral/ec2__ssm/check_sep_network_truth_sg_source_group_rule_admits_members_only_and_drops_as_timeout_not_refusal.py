"""sep-network-truth-sg-source-group-rule-admits-members-only-and-drops-as-timeout-not-refusal."""
from __future__ import annotations

import base64
import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-network-truth-sg-source-group-rule-admits-members-only-and-drops-as-timeout-not-refusal"
GROUP = "security-group-data-plane"
SERVICES = ["ec2", "ssm"]

_VPC_CIDR = "10.83.0.0/16"
_SUBNET_CIDR = "10.83.1.0/24"
_SERVER_IP = "10.83.1.10"
_LISTEN_PORT = 8080
_CLOSED_PORT = 8081  # admitted by the same rule, but nothing listens on it
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_SCENARIO = "sep-network-truth-sg-source-group"
# Failure marker attached only to legs asserting a connection must complete.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ingress rule naming a source group admits only that group's members; a packet it does not
    admit is dropped (connect timeout), unlike an admitted packet to a closed port (refused).

    Reference: https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    st: dict = {"instances": [], "sgs": [], "subnets": [], "igws": [], "vpcs": []}
    # Teardown runs in-band: registered cleanups get too little time for instance termination
    # plus ENI drain.
    try:
        _build(ctx, ec2, ssm, iam, st)
        _legs(ec2, ssm, st, ctx=ctx)
    finally:
        _teardown(ec2, iam, st, ctx=ctx)


def _build(ctx, ec2, ssm, iam, st) -> None:
    name = ctx.unique_name("sim2real-sntsg-")
    st["name"] = st["nonce"] = name
    zone = _usable_zones(ec2, want=1)[0]

    vpc = _create_public_vpc(ctx, ec2, st, _VPC_CIDR, name)
    subnet = _create_subnet(ctx, ec2, st, vpc, _SUBNET_CIDR, zone, name)

    sg_client = _create_sg(ctx, ec2, st, vpc, name + "-client", "sim2real snt referenced client")
    sg_other = _create_sg(ctx, ec2, st, vpc, name + "-other", "sim2real snt unreferenced group")
    sg_server = _create_sg(ctx, ec2, st, vpc, name + "-server", "sim2real snt server")
    st.update(sg_client=sg_client, sg_other=sg_other, sg_server=sg_server)

    _create_instance_role(ctx, iam, st, name + "-role")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    st["server"] = _launch(ctx, ec2, st, ami, subnet, sg_server, name + "-server",
                           user_data=_server_user_data(st["nonce"]), private_ip=_SERVER_IP)
    st["client"] = _launch(ctx, ec2, st, ami, subnet, sg_client, name + "-client")

    for label in ("server", "client"):
        _wait_online(ssm, st[label], label, ctx=ctx)

    inst = _describe_instance(ec2, st["client"])
    st["client_ip"] = inst["PrivateIpAddress"]
    enis = inst["NetworkInterfaces"]
    assert len(enis) == 1, f"the client must have exactly one ENI, it has {enis!r}"
    st["client_eni"] = enis[0]["NetworkInterfaceId"]
    assert [g["GroupId"] for g in enis[0]["Groups"]] == [sg_client], (
        f"the client ENI must start in exactly the referenced group {sg_client!r}: {enis[0]!r}")
    assert _describe_instance(ec2, st["server"])["PrivateIpAddress"] == _SERVER_IP, (
        "the server did not take the fixed private address the legs target")


def _legs(ec2, ssm, st, *, ctx) -> None:
    sg_server, sg_client, sg_other = st["sg_server"], st["sg_client"], st["sg_other"]
    ports = (_LISTEN_PORT, _CLOSED_PORT)

    # Nothing is interpretable unless the server answers its own listener.
    base = _server_view(ssm, st, ctx=ctx)
    assert base["local"] == st["nonce"], (
        f"the server must answer its own listener on 127.0.0.1 before any leg runs; it returned "
        f"{base['local']!r}, expected {st['nonce']!r}")
    assert _ingress(ec2, sg_server) == [], (
        f"a fresh security group must carry no ingress rules: {_ingress(ec2, sg_server)!r}")

    # L1: no ingress rule, so both ports are dropped (timeout), even the one with no listener.
    l1 = _probe(ssm, st, ports, ctx=ctx)
    assert l1[_LISTEN_PORT]["outcome"] == "timeout", (
        f"L1: with no ingress rule the packet must be dropped and the connect must TIME OUT; "
        f"got {l1[_LISTEN_PORT]!r}")
    assert l1[_CLOSED_PORT]["outcome"] == "timeout", (
        f"L1: a security-group drop is silent, so even a port with no listener must TIME OUT "
        f"rather than be REFUSED; got {l1[_CLOSED_PORT]!r}")
    after1 = _server_view(ssm, st, ctx=ctx)
    assert after1["local"] == st["nonce"], f"L1: the server stopped serving itself: {after1!r}"
    assert after1["hits"] == base["hits"], (
        f"L1: a dropped SYN must never reach the listener; the server logged "
        f"{base['hits']!r} -> {after1['hits']!r} requests from {st['client_ip']!r}")

    # L2: admit members of the client's group; the closed port now answers REFUSED.
    ec2.authorize_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _LISTEN_PORT, "ToPort": _CLOSED_PORT,
                        "UserIdGroupPairs": [{"GroupId": sg_client,
                                              "Description": "sim2real snt source group"}]}])
    rules = _ingress(ec2, sg_server)
    assert len(rules) == 1 and [p["GroupId"] for p in rules[0]["UserIdGroupPairs"]] == [sg_client], (
        f"L2: the server must hold exactly one rule naming {sg_client!r}: {rules!r}")
    assert rules[0]["IpRanges"] == [], f"L2: the rule must not admit by CIDR at all: {rules!r}"
    l2 = _poll(lambda: _probe(ssm, st, ports, ctx=ctx),
               lambda r: r[_LISTEN_PORT]["outcome"] == "ok", timeout_s=180, interval_s=1,
               what=f"{DATAPLANE_MARKER}: L2 a member of {sg_client!r} reaching "
                    f"{_SERVER_IP}:{_LISTEN_PORT} after the source-group rule", ctx=ctx)
    assert st["nonce"] in l2[_LISTEN_PORT]["response"], (
        f"{DATAPLANE_MARKER}: L2 connected but did not read the server's nonce "
        f"{st['nonce']!r}: {l2[_LISTEN_PORT]!r}")
    assert l2[_CLOSED_PORT]["outcome"] == "refused", (
        f"L2: the rule admits {_CLOSED_PORT}, where nothing listens, so the guest kernel must "
        f"answer with a reset and the client must see CONNECTION REFUSED -- not the TIMEOUT it "
        f"saw in L1 ({l1[_CLOSED_PORT]!r}); got {l2[_CLOSED_PORT]!r}")
    after2 = _server_view(ssm, st, ctx=ctx)
    assert after2["hits"] > after1["hits"], (
        f"L2: the admitted request must appear in the server's own access log: "
        f"{after1['hits']!r} -> {after2['hits']!r}")

    # L3: same client IP, but no longer a member of the referenced group.
    ec2.modify_network_interface_attribute(NetworkInterfaceId=st["client_eni"], Groups=[sg_other])
    assert _eni_groups(ec2, st["client_eni"]) == [sg_other], (
        f"L3: the client ENI must now be only in {sg_other!r}: "
        f"{_eni_groups(ec2, st['client_eni'])!r}")
    assert _describe_instance(ec2, st["client"])["PrivateIpAddress"] == st["client_ip"], (
        "L3: the client's address must be unchanged, so only group membership differs")
    l3 = _poll(lambda: _probe(ssm, st, (_LISTEN_PORT,), ctx=ctx),
               lambda r: r[_LISTEN_PORT]["outcome"] != "ok", timeout_s=180, interval_s=1,
               what="L3 the non-member client being dropped", ctx=ctx)
    assert l3[_LISTEN_PORT]["outcome"] == "timeout", (
        f"L3: a source-group rule matches MEMBERSHIP, so the same host at the same address "
        f"outside {sg_client!r} must be dropped (TIMEOUT); got {l3[_LISTEN_PORT]!r}")
    base3 = _server_view(ssm, st, ctx=ctx)
    l3b = _probe(ssm, st, (_LISTEN_PORT,), ctx=ctx)
    after3 = _server_view(ssm, st, ctx=ctx)
    assert l3b[_LISTEN_PORT]["outcome"] == "timeout", f"L3: not stable: {l3b!r}"
    assert after3["local"] == st["nonce"], f"L3: the server stopped serving itself: {after3!r}"
    assert after3["hits"] == base3["hits"], (
        f"L3: a dropped SYN must never reach the listener: {base3['hits']!r} -> "
        f"{after3['hits']!r}")

    # L4: back into the referenced group, so admitted again.
    ec2.modify_network_interface_attribute(NetworkInterfaceId=st["client_eni"], Groups=[sg_client])
    l4 = _poll(lambda: _probe(ssm, st, (_LISTEN_PORT,), ctx=ctx),
               lambda r: r[_LISTEN_PORT]["outcome"] == "ok", timeout_s=180, interval_s=1,
               what=f"{DATAPLANE_MARKER}: L4 the client, a member again, reaching the server",
               ctx=ctx)
    assert st["nonce"] in l4[_LISTEN_PORT]["response"], (
        f"{DATAPLANE_MARKER}: L4 did not read the nonce: {l4[_LISTEN_PORT]!r}")

    # L5: revoke, so dropped again.
    ec2.revoke_security_group_ingress(
        GroupId=sg_server,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _LISTEN_PORT, "ToPort": _CLOSED_PORT,
                        "UserIdGroupPairs": [{"GroupId": sg_client}]}])
    assert _ingress(ec2, sg_server) == [], (
        f"L5: the revoke must leave zero ingress rules: {_ingress(ec2, sg_server)!r}")
    l5 = _poll(lambda: _probe(ssm, st, ports, ctx=ctx),
               lambda r: r[_LISTEN_PORT]["outcome"] != "ok"
               and r[_CLOSED_PORT]["outcome"] != "refused",
               timeout_s=180, interval_s=1, what="L5 both ports dropped after the revoke", ctx=ctx)
    assert l5[_LISTEN_PORT]["outcome"] == "timeout", (
        f"L5: after the revoke the connect must TIME OUT again; got {l5[_LISTEN_PORT]!r}")
    assert l5[_CLOSED_PORT]["outcome"] == "timeout", (
        f"L5: after the revoke the no-listener port must be dropped (TIMEOUT), not REFUSED; got "
        f"{l5[_CLOSED_PORT]!r}")
    final = _server_view(ssm, st, ctx=ctx)
    assert final["local"] == st["nonce"], f"L5: the server stopped serving itself: {final!r}"


def _teardown(ec2, iam, st, *, ctx) -> list:
    """Ordered teardown with waits. Runs every step, then raises what it could not remove, naming
    any failure in flight so it is not masked."""
    left: list = []
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    def _vpc_gone(vpc_id):
        still = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
        raise AssertionError(f"vpc {vpc_id} is still describable: {still!r}")

    if st["instances"]:
        _step("terminate", lambda: ec2.terminate_instances(InstanceIds=list(st["instances"])))
        for iid in st["instances"]:
            _step(f"terminated {iid}", lambda i=iid: _wait_terminated(ec2, i, ctx=ctx))
    for vpc in st["vpcs"]:
        _step(f"eni-drain {vpc}", lambda v=vpc: _poll(
            lambda: _vpc_enis(ec2, v), lambda e: e == [], timeout_s=300, interval_s=2,
            what=f"every ENI in {v} draining", capped=False, ctx=ctx))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    for sg in reversed(st["sgs"]):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st["subnets"]:
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    for igw, vpc in st["igws"]:
        _step(f"igw-detach {igw}", lambda g=igw, v=vpc: ec2.detach_internet_gateway(
            InternetGatewayId=g, VpcId=v))
        _step(f"igw {igw}", lambda g=igw: ec2.delete_internet_gateway(InternetGatewayId=g))
    for vpc in st["vpcs"]:
        _step(f"vpc {vpc}", lambda v=vpc: _retry_dependency(lambda: ec2.delete_vpc(VpcId=v)))
        _step(f"vpc-gone {vpc}", lambda v=vpc: _vpc_gone(v))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 -- collected, raised after every step
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")
    return left


_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached")

# Runs INSIDE the client instance. Classifies each TCP connect as ok / timeout / refused so the
# host never has to infer the outcome from an exit code.
_PROBE_PY = r'''
import json, socket, sys
host = sys.argv[1]
out = {}
for port in [int(p) for p in sys.argv[2:]]:
    d = {"port": port}
    try:
        s = socket.create_connection((host, port), timeout=2)
    except socket.timeout:
        d["outcome"] = "timeout"
    except ConnectionRefusedError:
        d["outcome"] = "refused"
    except OSError as e:
        d["outcome"] = "oserror"; d["errno"] = e.errno; d["msg"] = str(e)
    else:
        try:
            s.settimeout(5)
            s.sendall(b"GET /nonce HTTP/1.0\r\nHost: sim2real\r\n\r\n")
            buf = b""
            while True:
                b = s.recv(4096)
                if not b:
                    break
                buf += b
            d["outcome"] = "ok"; d["response"] = buf.decode("utf-8", "replace")[-400:]
        except socket.timeout:
            d["outcome"] = "read-timeout"
        finally:
            s.close()
    out[str(port)] = d
print(json.dumps(out))
'''


def _server_user_data(nonce):
    return (
        "#!/bin/bash\n"
        "mkdir -p /tmp/srv\n"
        f"printf '%s' '{nonce}' > /tmp/srv/nonce\n"
        "cd /tmp/srv\n"
        f"nohup python3 -m http.server {_LISTEN_PORT} --bind 0.0.0.0 > /tmp/httpd.log 2>&1 &\n"
    )


def _unless_gone(fn, *codes):
    """A backup cleanup the in-band teardown may already have done: only *codes* (the resource's
    own not-found) count as done; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _tags_for(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": _SCENARIO}]


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
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= want, f"this region offers {_INSTANCE_TYPE} only in {usable!r}"
    return usable[:want]


def _create_public_vpc(ctx, ec2, st, cidr, name):
    """A VPC whose main route table sends 0.0.0.0/0 to its own internet gateway, so each
    instance's SSM agent reaches the public SSM endpoint with no interface endpoints."""
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    st["vpcs"].append(vpc)
    ctx.on_cleanup(lambda: _unless_gone(lambda: ec2.delete_vpc(VpcId=vpc), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags_for(name)}])[
        "InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw),
        "InvalidInternetGatewayID.NotFound"))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    st["igws"].append((igw, vpc))
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc),
        "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached"))
    rtb = _main_route_table(ec2, vpc)
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    return vpc


def _main_route_table(ec2, vpc):
    tables = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"]
    assert len(tables) == 1, f"expected one main route table in {vpc}, got {tables!r}"
    return tables[0]["RouteTableId"]


def _create_subnet(ctx, ec2, st, vpc, cidr, zone, name):
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=zone,
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    st["subnets"].append(subnet)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_subnet(SubnetId=subnet), "InvalidSubnetID.NotFound"))
    return subnet


def _create_sg(ctx, ec2, st, vpc, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: ec2.delete_security_group(GroupId=sg), "InvalidGroup.NotFound"))
    return sg


def _create_instance_role(ctx, iam, st, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real sep-network-truth in-VPC probe",
                    Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    st["role"] = role_name
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY),
        "NoSuchEntity"))
    iam.create_instance_profile(InstanceProfileName=role_name,
                                Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    st["profile"] = role_name
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.delete_instance_profile(InstanceProfileName=role_name), "NoSuchEntity"))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name),
        "NoSuchEntity"))
    # IAM exposes no "profile usable" condition; _launch's bounded retry on
    # InvalidParameterValue is what makes first use correct.


def _drop_instance_profile(iam, profile, role):
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    iam.delete_instance_profile(InstanceProfileName=profile)


def _drop_role(iam, role):
    try:
        iam.detach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    _call_with_retry(lambda: iam.delete_role(RoleName=role), codes=("DeleteConflict",),
                     retries=25, delay=2.0)


def _launch(ctx, ec2, st, ami, subnet, sg, tag_name, user_data=None, private_ip=None):
    nic = {"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg], "AssociatePublicIpAddress": True}
    if private_ip:
        nic["PrivateIpAddress"] = private_ip
    kwargs = dict(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        NetworkInterfaces=[nic], IamInstanceProfile={"Name": st["profile"]},
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume", "network-interface")],
    )
    if user_data:
        kwargs["UserData"] = base64.b64encode(user_data.encode()).decode()
    iid = _call_with_retry(lambda: ec2.run_instances(**kwargs),
                           codes=_THROTTLE + ("InvalidParameterValue",), retries=60,
                           delay=2.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[iid]))
    return iid


def _describe_instance(ec2, iid):
    resv = _call_with_retry(lambda: ec2.describe_instances(InstanceIds=[iid]),
                            codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=30,
                            delay=2.0)["Reservations"]
    return resv[0]["Instances"][0]


def _wait_terminated(ec2, iid, timeout_s=420, *, ctx):
    _poll(lambda: _describe_instance(ec2, iid)["State"]["Name"], lambda s: s == "terminated",
          timeout_s=timeout_s, interval_s=2, what=f"instance {iid} terminated", capped=False,
          ctx=ctx)


def _vpc_enis(ec2, vpc):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkInterfaces"]]


def _eni_groups(ec2, eni):
    return [g["GroupId"] for g in ec2.describe_network_interfaces(
        NetworkInterfaceIds=[eni])["NetworkInterfaces"][0]["Groups"]]


def _ingress(ec2, sg):
    return ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]["IpPermissions"]


def _wait_online(ssm, iid, label, *, ctx):
    def _view():
        infos = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [iid]}])["InstanceInformationList"]
        return infos[0] if infos else None
    info = _poll(_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=720, interval_s=2,
                 what=f"the SSM agent on the {label} {iid} coming Online", ctx=ctx)
    assert info["InstanceId"] == iid, f"SSM answered for the wrong instance: {info!r}"


def _run(ssm, iid, script, timeout_s=300, *, ctx):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[iid], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real sep-network-truth probe"),
        codes=_THROTTLE + ("InvalidInstanceId",), retries=60, delay=2.0)
    cid = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise
    inv = _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=timeout_s, interval_s=1.0, what=f"command {cid} on {iid} finishing",
                ctx=ctx)
    assert inv["Status"] == "Success" and inv["ResponseCode"] == 0, (
        f"the control command itself failed on {iid}: status={inv['Status']!r} "
        f"rc={inv['ResponseCode']!r} stderr={inv.get('StandardErrorContent')!r}")
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, f"the guest {iid} printed nothing: {inv!r}"
    return json.loads(lines[-1])


def _probe(ssm, st, ports, *, ctx):
    script = ("cat > /tmp/sim2real_probe.py <<'PYEOF'\n" + _PROBE_PY + "PYEOF\n"
              f"python3 /tmp/sim2real_probe.py {_SERVER_IP} " + " ".join(str(p) for p in ports))
    raw = _run(ssm, st["client"], script, ctx=ctx)
    return {int(k): v for k, v in raw.items()}


def _server_view(ssm, st, *, ctx):
    script = (
        f"LOCAL=$(curl -s -m 5 http://127.0.0.1:{_LISTEN_PORT}/nonce || true)\n"
        f"HITS=$(grep -c '^{st['client_ip'] if st.get('client_ip') else 'none'} ' "
        "/tmp/httpd.log || true)\n"
        "printf '{\"local\": \"%s\", \"hits\": %d}\\n' \"$LOCAL\" \"${HITS:-0}\"\n")
    return _run(ssm, st["server"], script, ctx=ctx)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
