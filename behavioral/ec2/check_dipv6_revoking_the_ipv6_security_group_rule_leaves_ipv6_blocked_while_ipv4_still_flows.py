"""dipv6-revoking-the-ipv6-security-group-rule-leaves-ipv6-blocked-while-ipv4-still-flows."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dipv6-revoking-the-ipv6-security-group-rule-leaves-ipv6-blocked-while-ipv4-still-flows"
GROUP = 'ipv6-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_WANT_TYPE = "t3.micro"
_PORT = 8080

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """Call *fn*; return the AWS (code, message). An unexpected SUCCESS raises, so an over-permissive
    target's acceptance is reported as such, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


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


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded: a DependencyViolation that never clears is a leak to declare, not a loop to sit in.
    """
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                             "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
                             "InvalidAssociationID.NotFound", "InvalidGroup.NotFound",
                             "InvalidGatewayID.NotFound", "Gateway.NotAttached"):
                return None
            raise


def _az_for(ec2, want):
    """The first AZ that both OFFERS *want* and is reported available.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state, and
    describe_availability_zones says nothing about instance types. An empty intersection means this
    region cannot carry the check, which is a finding rather than an AZ to guess at.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {want!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _instance_profile(ctx, iam, scenario):
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-dipv6-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav ipv6 security-group independence role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    # Propagation is waited out by the bounded InvalidParameterValue retry on RunInstances.
    return role


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for attempt in range(12):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _instance_state(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_nowait(ec2, instance_ids):
    """Issue every terminate before any wait.

    Registered after the LAST RunInstances so that LIFO runs it FIRST: the per-instance
    terminate-and-wait nets registered immediately after each create then find both machines already
    shutting down, so teardown costs the MAX of the two waits rather than their sum. A summed
    teardown is how a wrapper timeout cuts the chain off mid-sequence and strands a running
    instance.
    """
    for iid in instance_ids:
        try:
            _call_with_retry(lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
        except ClientError as exc:
            if _code(exc) != "InvalidInstanceID.NotFound":
                raise


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', not merely 'shutting-down': the ENI, the security-group
    membership and the instance-profile association only clear at the end, and the subnet, security
    group and VPC teardown registered earlier cannot proceed until they do."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=420, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted rejects
    SendCommand with InvalidInstanceId until its agent has registered, so retrying that call polls
    an observable condition instead of sleeping a guessed interval. A host that never accepts a
    command is a FAIL — 'the machine never came up' is the fidelity defect this check exists to
    catch, not an environment limitation.
    """
    deadline = time.monotonic() + ready_timeout_s
    sent = None
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav ipv6 security-group independence",
            )
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_invocation, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=run_timeout_s, interval_s=5.0,
                what=f"{what}: invocation {command_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"{what}: the guest script was {inv['Status']!r} ({inv.get('StatusDetails')!r}); "
        f"rc={inv.get('ResponseCode')!r} stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"{what}: the guest script exited {inv['ResponseCode']!r}; "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _reports(stdout, marker, key="label"):
    """Every `key=value` line starting with *marker*, keyed by its *key* field."""
    out = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith(marker):
            continue
        fields = {}
        for field in line[len(marker):].split():
            if "=" in field:
                k, _, v = field.partition("=")
                fields[k] = v
        if key in fields:
            out[fields[key]] = fields
    return out


#: `%{remote_ip}` is the load-bearing field: it is the peer address the guest's kernel actually
#: connected to. The function never fails the script — the guest is a measuring instrument and the
#: check does the asserting, so a refused connection comes back as data rather than as an exit
#: status `_run_guest` would read as a broken script.
_PROBE_FUNC = [
    "probe() {",
    "  fam=$1; url=$2; label=$3",
    "  o=$(curl \"$fam\" -sS --max-time 12 -o /dev/null "
    "-w '%{http_code} %{remote_ip}' \"$url\" 2>/dev/null)",
    "  rc=$?",
    "  c=${o%% *}; r=${o##* }",
    "  if [ -z \"$c\" ]; then c=000; fi",
    "  if [ -z \"$r\" ]; then r=none; fi",
    "  echo \"SIM2REAL-P label=$label rc=$rc code=$c remote=$r\"",
    "}",
]

#: ONE listener on ONE port serving BOTH families, which is what makes the comparison exact: an
#: AF_INET6 socket with IPV6_V6ONLY cleared accepts IPv4 connections as v4-mapped addresses, so the
#: only difference between the two legs below is the address family of the packets — not the port,
#: not the process, not the socket. Detached with `setsid` so it outlives the Run Command
#: invocation that started it, and serving an empty directory.
_LISTENER = [
    "mkdir -p /tmp/sim2real-empty",
    "cat > /tmp/sim2real-srv.py <<'PYEOF'",
    "import http.server, socketserver, socket",
    "class S(socketserver.TCPServer):",
    "    address_family = socket.AF_INET6",
    "    allow_reuse_address = True",
    "    def server_bind(self):",
    "        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)",
    "        socketserver.TCPServer.server_bind(self)",
    "S(('::', %d), http.server.SimpleHTTPRequestHandler).serve_forever()" % _PORT,
    "PYEOF",
    "cd /tmp/sim2real-empty",
    "setsid nohup python3 /tmp/sim2real-srv.py >/tmp/sim2real-srv.log 2>&1 </dev/null &",
    "for i in $(seq 1 25); do",
    "  if ss -ltn 2>/dev/null | grep -q ':%d'; then break; fi" % _PORT,
    "  sleep 1",
    "done",
    "L=$(ss -ltn 2>/dev/null | grep ':%d' | head -1 | tr -s ' ' ',')" % _PORT,
    "echo \"SIM2REAL-ID label=listener listen=${L:-none}\"",
]


def _launch(ctx, ec2, ami, subnet, sg, profile, scenario, label):
    tagspec = [{"ResourceType": rt,
                "Tags": [{"Key": "sim2real", "Value": scenario},
                         {"Key": "Name", "Value": f"{scenario}-{label}"}]}
               for rt in ("instance", "volume")]
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_WANT_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet, SecurityGroupIds=[sg], IamInstanceProfile={"Name": profile},
            TagSpecifications=tagspec,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    return reservation["Instances"][0]["InstanceId"]


def _wait_online(ssm, instance_id):
    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    return _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=600, interval_s=5.0,
                 what=f"the SSM agent on {instance_id} coming Online")


def _addresses(ec2, instance_id, subnet_v6):
    """The instance's sole private IPv4 and sole global IPv6 address."""
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    enis = inst["NetworkInterfaces"]
    assert len(enis) == 1, f"expected exactly one ENI on {instance_id}, got {enis!r}"
    v6 = [a["Ipv6Address"] for a in enis[0].get("Ipv6Addresses", [])]
    assert len(v6) == 1, (
        f"the subnet's AssignIpv6AddressOnCreation must give {instance_id} exactly one IPv6 "
        f"address, got {v6!r}"
    )
    addr6 = ipaddress.IPv6Address(v6[0])
    assert addr6 in subnet_v6, f"{addr6!s} is outside its own subnet range {subnet_v6!s}"
    assert addr6.is_global, (
        f"the address must be globally routable unicast, but {addr6!s} is not "
        f"(link_local={addr6.is_link_local}, private={addr6.is_private})"
    )
    addr4 = ipaddress.IPv4Address(inst["PrivateIpAddress"])
    return addr4, addr6


def _ingress_rules(ec2, group_id):
    rules = []
    for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [group_id]}]):
        rules += page["SecurityGroupRules"]
    return [r for r in rules if not r["IsEgress"]]


def _egress_rules(ec2, group_id):
    rules = []
    for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [group_id]}]):
        rules += page["SecurityGroupRules"]
    return [r for r in rules if r["IsEgress"]]


# ===== end helpers =====


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A security-group ingress rule on the IPv6 family governs only IPv6: revoking it stops IPv6 traffic
    to the port while the IPv4 rule keeps admitting IPv4 to the same socket, and revoking the IPv4
    rule instead produces the mirror image."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dipv6-sg-family-independence"
    cidr4 = "10.183.0.0/16"

    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario},
                                              {"Key": "Name", "Value": scenario}]}]

    # --- everything decidable, before anything is created ---------------------
    az = _az_for(ec2, _WANT_TYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    # --- one dual-stack VPC of this check's own making ------------------------
    vpc = ec2.create_vpc(CidrBlock=cidr4, TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))

    assoc = ec2.associate_vpc_cidr_block(VpcId=vpc, AmazonProvidedIpv6CidrBlock=True)
    v6_assoc_id = assoc["Ipv6CidrBlockAssociation"]["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.disassociate_vpc_cidr_block(AssociationId=v6_assoc_id)))

    def _v6_assoc():
        for a in ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"][0].get("Ipv6CidrBlockAssociationSet", []):
            if a["AssociationId"] == v6_assoc_id:
                return a
        return None

    v6 = _poll(_v6_assoc,
               lambda a: a is not None and a["Ipv6CidrBlockState"]["State"] == "associated",
               timeout_s=180, interval_s=3.0,
               what=f"the Amazon-provided IPv6 CIDR on {vpc} reaching 'associated'")
    subnet_v6 = next(ipaddress.IPv6Network(v6["Ipv6CidrBlock"]).subnets(new_prefix=64))

    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))

    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.183.1.0/24", Ipv6CidrBlock=str(subnet_v6),
                               AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    ec2.modify_subnet_attribute(SubnetId=subnet, AssignIpv6AddressOnCreation={"Value": True})

    rtb = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=tagspec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rtb)))
    # IPv4 only: the SSM agent needs egress, and this check deliberately gives the VPC NO IPv6 path
    # off-net.
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    rtb_assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.disassociate_route_table(AssociationId=rtb_assoc)))

    # --- the two security groups ---------------------------------------------
    server_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-dipv6-srv-"), VpcId=vpc,
        Description="sim2real-behav ipv6 sg-family server",
        TagSpecifications=tagspec("security-group"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=server_sg)))
    client_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-dipv6-cli-"), VpcId=vpc,
        Description="sim2real-behav ipv6 sg-family client",
        TagSpecifications=tagspec("security-group"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=client_sg)))
    # The default egress rules follow the VPC's ADDRESS FAMILIES rather than being a fixed IPv4
    # default: a group created in a dual-stack VPC arrives with TWO all-protocol egress rules,
    # 0.0.0.0/0 and ::/0. Authorizing ::/0 egress explicitly here is refused as
    # InvalidPermission.Duplicate. Asserted rather than assumed, because it is what makes the
    # absent legs below attributable to the SERVER's ingress rules: if the client's own egress did
    # not already permit ::/0, every IPv6 failure would be its own group's doing.
    for gid, whose in ((server_sg, "server"), (client_sg, "client")):
        egress = {(r.get("IpProtocol"), r.get("CidrIpv4") or r.get("CidrIpv6"))
                  for r in _egress_rules(ec2, gid)}
        assert egress == {("-1", "0.0.0.0/0"), ("-1", "::/0")}, (
            f"the {whose} group must come with all-protocol egress for BOTH families, got "
            f"{sorted(egress)!r} in {gid}"
        )

    def _authorize_v6():
        return ec2.authorize_security_group_ingress(
            GroupId=server_sg,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                            "Ipv6Ranges": [{"CidrIpv6": str(subnet_v6)}]}],
        )["SecurityGroupRules"][0]["SecurityGroupRuleId"]

    v6_rule_id = _authorize_v6()
    v4_rule_id = ec2.authorize_security_group_ingress(
        GroupId=server_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                        "IpRanges": [{"CidrIp": cidr4}]}],
    )["SecurityGroupRules"][0]["SecurityGroupRuleId"]

    # The two rules are separate objects with separate ids, which is the premise of the whole check:
    # if the target merged them, revoking one could not leave the other in place.
    assert v6_rule_id != v4_rule_id, (
        f"the IPv6 and IPv4 ingress rules for tcp/{_PORT} must be distinct objects, but both came "
        f"back as {v6_rule_id!r}"
    )
    rules = {r["SecurityGroupRuleId"]: r for r in _ingress_rules(ec2, server_sg)}
    assert set(rules) == {v6_rule_id, v4_rule_id}, (
        f"the server group must hold exactly the two ingress rules just authorized, got "
        f"{sorted(rules)!r}"
    )
    assert rules[v6_rule_id].get("CidrIpv6") == str(subnet_v6) and "CidrIpv4" not in rules[v6_rule_id], (
        f"the IPv6 rule must carry CidrIpv6 and no CidrIpv4: {rules[v6_rule_id]!r}"
    )
    assert rules[v4_rule_id].get("CidrIpv4") == cidr4 and "CidrIpv6" not in rules[v4_rule_id], (
        f"the IPv4 rule must carry CidrIpv4 and no CidrIpv6: {rules[v4_rule_id]!r}"
    )

    # A rule is identified by protocol, port range AND family, so re-authorizing the IPv6 entry is a
    # duplicate. The positive control for this negative is the rule that exists and is about to
    # carry real bytes.
    code, message = _error(_authorize_v6)
    assert code == "InvalidPermission.Duplicate", (
        f"re-authorizing the identical IPv6 tcp/{_PORT} ingress rule must be refused with "
        f"InvalidPermission.Duplicate, got {code!r}"
    )
    assert message == (f'the specified rule "peer: {subnet_v6}, TCP, from port: {_PORT}, to port: '
                       f'{_PORT}, ALLOW" already exists'), message

    profile = _instance_profile(ctx, iam, scenario)

    # --- two instances, terminate registered immediately after each launch ----
    server_id = _launch(ctx, ec2, ami, subnet, server_sg, profile, scenario, "server")
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, server_id))
    client_id = _launch(ctx, ec2, ami, subnet, client_sg, profile, scenario, "client")
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, client_id))
    # Registered last so LIFO runs it first: both terminates are issued before either wait begins.
    ctx.on_cleanup(lambda: _terminate_nowait(ec2, [server_id, client_id]))

    for iid in (server_id, client_id):
        _poll(lambda i=iid: _instance_state(ec2, i), lambda s: s == "running",
              timeout_s=600, interval_s=5.0, what=f"instance {iid} reaching 'running'")
    server4, server6 = _addresses(ec2, server_id, subnet_v6)
    client4, client6 = _addresses(ec2, client_id, subnet_v6)
    assert client4 in ipaddress.IPv4Network(cidr4), (
        f"the client's private address {client4!s} must fall inside {cidr4}, or the IPv4 ingress "
        f"rule would not cover it and the IPv4 control leg would be meaningless"
    )
    for iid in (server_id, client_id):
        _wait_online(ssm, iid)

    url6 = f"http://[{server6!s}]:{_PORT}/"
    url4 = f"http://{server4!s}:{_PORT}/"

    # --- the listener answers on BOTH families, before any rule is touched ----
    # Traffic to an instance's own address never traverses a security group, so this isolates the
    # dual-family listener from the enforcement question entirely.
    server_out = _run_guest(ssm, server_id,
                            ["set -uo pipefail"] + _LISTENER + _PROBE_FUNC + [
                                f"probe -6 '{url6}' self6",
                                f"probe -4 '{url4}' self4",
                            ], "starting the dual-family listener")
    listener = _reports(server_out, "SIM2REAL-ID").get("listener")
    assert listener and listener["listen"] != "none", (
        f"the server never opened tcp/{_PORT}; `ss -ltn` showed nothing. stdout was {server_out!r}"
    )
    selves = _reports(server_out, "SIM2REAL-P")
    assert selves.get("self6", {}).get("code") == "200", (
        f"the one listener must answer on the server's OWN IPv6 address, or nothing below isolates "
        f"the security group: {selves.get('self6')!r}; stdout {server_out!r}"
    )
    assert selves.get("self4", {}).get("code") == "200", (
        f"the same listener must answer on the server's OWN IPv4 address, which is what makes the "
        f"two legs differ only in address family: {selves.get('self4')!r}; stdout {server_out!r}"
    )

    def _client_probe(label6, label4, what):
        out = _run_guest(ssm, client_id, ["set -uo pipefail"] + _PROBE_FUNC + [
            f"probe -6 '{url6}' {label6}",
            f"probe -4 '{url4}' {label4}",
        ], what)
        return _reports(out, "SIM2REAL-P"), out

    # --- baseline: both rules present, both families admitted ----------------
    base, out = _client_probe("base6", "base4", "the baseline probe from the client")
    assert base.get("base6", {}).get("code") == "200", (
        f"with the IPv6 rule in place the client must reach {url6} and get HTTP 200, got "
        f"{base.get('base6')!r}; stdout {out!r}"
    )
    assert ":" in base["base6"]["remote"], (
        f"the IPv6 leg did not travel over IPv6: {base['base6']!r}"
    )
    assert base.get("base4", {}).get("code") == "200", (
        f"with the {cidr4} IPv4 rule in place the client must reach {url4} and get HTTP 200, got "
        f"{base.get('base4')!r}; stdout {out!r}"
    )
    assert ":" not in base["base4"]["remote"], (
        f"the IPv4 leg did not travel over IPv4: {base['base4']!r}"
    )

    # --- break exactly ONE thing: the IPv6 rule -------------------------------
    ec2.revoke_security_group_ingress(GroupId=server_sg, SecurityGroupRuleIds=[v6_rule_id])
    left = {r["SecurityGroupRuleId"] for r in _ingress_rules(ec2, server_sg)}
    assert left == {v4_rule_id}, (
        f"after revoking {v6_rule_id} the server group must hold only the IPv4 rule, got {left!r}"
    )

    state = {}

    def _after_v6_revoke():
        state["r"], state["out"] = _client_probe("nov6", "nov6_control4",
                                                "probing after the IPv6 rule was revoked")
        return state["r"]

    blocked = _poll(_after_v6_revoke,
                    lambda p: p.get("nov6", {}).get("rc") not in (None, "0"),
                    timeout_s=240, interval_s=5.0,
                    what=f"IPv6 to {url6} ceasing after the IPv6 rule was revoked")
    assert blocked["nov6"]["code"] == "000", (
        f"with no IPv6 ingress rule the request must not complete, but the client still got HTTP "
        f"{blocked['nov6']['code']!r} from {blocked['nov6']['remote']!r}"
    )
    assert blocked.get("nov6_control4", {}).get("code") == "200", (
        f"revoking the IPv6 rule must not touch IPv4: the IPv4 leg to the SAME socket reported "
        f"{blocked.get('nov6_control4')!r}, so the IPv6 failure above is not attributable to the "
        f"rule's family. stdout {state.get('out')!r}"
    )

    # --- the mirror image: restore IPv6, revoke IPv4 instead -----------------
    v6_rule_id_2 = _authorize_v6()
    ec2.revoke_security_group_ingress(GroupId=server_sg, SecurityGroupRuleIds=[v4_rule_id])
    left = {r["SecurityGroupRuleId"] for r in _ingress_rules(ec2, server_sg)}
    assert left == {v6_rule_id_2}, (
        f"after restoring the IPv6 rule and revoking {v4_rule_id} the server group must hold only "
        f"the new IPv6 rule {v6_rule_id_2!r}, got {left!r}"
    )

    def _after_v4_revoke():
        state["r"], state["out"] = _client_probe("nov4_control6", "nov4",
                                                "probing after the IPv4 rule was revoked")
        return state["r"]

    mirrored = _poll(_after_v4_revoke,
                     lambda p: (p.get("nov4", {}).get("rc") not in (None, "0")
                               and p.get("nov4_control6", {}).get("code") == "200"),
                     timeout_s=240, interval_s=5.0,
                     what=f"IPv4 to {url4} ceasing, and IPv6 resuming, after the swap")
    assert mirrored["nov4"]["code"] == "000", (
        f"with no IPv4 ingress rule the IPv4 request must not complete, but the client still got "
        f"HTTP {mirrored['nov4']['code']!r} from {mirrored['nov4']['remote']!r}"
    )
    assert ":" in mirrored["nov4_control6"]["remote"], (
        f"the restored IPv6 leg did not travel over IPv6: {mirrored['nov4_control6']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
