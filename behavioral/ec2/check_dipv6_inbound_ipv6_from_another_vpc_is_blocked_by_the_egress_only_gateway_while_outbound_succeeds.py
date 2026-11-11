"""dipv6-inbound-ipv6-from-another-vpc-is-blocked-by-the-egress-only-gateway-while-outbound-succeeds."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dipv6-inbound-ipv6-from-another-vpc-is-blocked-by-the-egress-only-gateway-while-outbound-succeeds"
GROUP = 'ipv6-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_WANT_TYPE = "t3.micro"
_PORT = 8080
#: AWS's own dual-stack endpoint for this region, derived from ctx.region. See the docstring.
_DUAL_STACK_HOST_FMT = "https://dynamodb.{region}.api.aws/"


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error_code(fn):
    """Call *fn*; return the AWS error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc)
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
                    Description="sim2real-behav egress-only one-way role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    # IAM propagation exposes no condition to poll: no API reports that a freshly created instance
    # profile has become resolvable by RunInstances. The bounded retry on the RunInstances call is
    # what makes this correct; this sleep only makes it cheaper.
    time.sleep(10)
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
                Comment="sim2real-behav egress-only one-way data plane",
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


#: The function never fails the script — the guest is a measuring instrument and the check does the
#: asserting, so a refused connection comes back as data rather than as an exit status `_run_guest`
#: would read as a broken script.
_PROBE_FUNC = [
    "probe() {",
    "  fam=$1; url=$2; label=$3",
    "  o=$(curl \"$fam\" -sS --max-time 15 -o /dev/null "
    "-w '%{http_code} %{remote_ip}' \"$url\" 2>/dev/null)",
    "  rc=$?",
    "  c=${o%% *}; r=${o##* }",
    "  if [ -z \"$c\" ]; then c=000; fi",
    "  if [ -z \"$r\" ]; then r=none; fi",
    "  echo \"SIM2REAL-P label=$label rc=$rc code=$c remote=$r\"",
    "}",
]

#: The listener, written into the guest and detached with `setsid` so it outlives the Run Command
#: invocation that started it. AF_INET6 explicitly rather than relying on `python3 -m http.server
#: --bind ::` inferring the family, and it serves an empty directory.
_LISTENER = [
    "mkdir -p /tmp/sim2real-empty",
    "cat > /tmp/sim2real-srv.py <<'PYEOF'",
    "import http.server, socketserver, socket",
    "class S(socketserver.TCPServer):",
    "    address_family = socket.AF_INET6",
    "    allow_reuse_address = True",
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


def _dual_stack_egress_only_vpc(ctx, ec2, az, cidr4, subnet4, scenario, label):
    """A dual-stack VPC with an internet gateway for IPv4 and an EGRESS-ONLY gateway for IPv6.

    Deliberately not the account's default VPC: a fresh account need not have one, and a shared default
    subnet would make the check assert a property of the account. Every
    piece is tagged at creation.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario},
                                              {"Key": "Name", "Value": f"{scenario}-{label}"}]}]

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
    vpc_v6_net = ipaddress.IPv6Network(v6["Ipv6CidrBlock"])
    subnet_v6 = next(vpc_v6_net.subnets(new_prefix=64))

    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))

    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=subnet4, Ipv6CidrBlock=str(subnet_v6),
                               AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    ec2.modify_subnet_attribute(SubnetId=subnet, AssignIpv6AddressOnCreation={"Value": True})

    eoigw = ec2.create_egress_only_internet_gateway(
        VpcId=vpc, TagSpecifications=tagspec("egress-only-internet-gateway"),
    )["EgressOnlyInternetGateway"]["EgressOnlyInternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eoigw)))

    rtb = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=tagspec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rtb)))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.create_route(RouteTableId=rtb, DestinationIpv6CidrBlock="::/0",
                     EgressOnlyInternetGatewayId=eoigw)
    rtb_assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.disassociate_route_table(AssociationId=rtb_assoc)))

    # The one-way property is enforced at the ROUTE TABLE, not just per route: once any IPv6 route
    # in this table has the egress-only gateway as its next hop, AWS refuses to add an IPv6 route
    # via the internet gateway — even for an unrelated destination, which is what makes the code
    # attributable to the mixing rule rather than to a duplicate destination. Measured; the message
    # names the egress-only gateway as the reason. A table that accepted both would be two-way for
    # IPv6 behind a gateway advertised as one-way, so an emulator that allows it has broken the very
    # guarantee this check goes on to measure in packets. The positive control is the ::/0 route
    # asserted just below, which is about to carry real bytes.
    code = _error_code(lambda: ec2.create_route(
        RouteTableId=rtb, DestinationIpv6CidrBlock="2001:db8::/32", GatewayId=igw))
    assert code == "OperationNotPermitted", (
        f"{label}: adding an IPv6 route via {igw} to a table whose IPv6 next hop is the egress-only "
        f"gateway must be refused with OperationNotPermitted, got {code!r}"
    )

    routes = ec2.describe_route_tables(RouteTableIds=[rtb])["RouteTables"][0]["Routes"]
    # The refusal above is IPv6-scoped: the IPv4 default via the SAME internet gateway survives it,
    # which is why the instances can still reach SSM and be asked what they saw.
    v4_default = [r for r in routes if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert len(v4_default) == 1 and v4_default[0].get("GatewayId") == igw, (
        f"{label}: the IPv4 default via {igw!r} must survive the IPv6 refusal, found {v4_default!r}"
    )
    assert not [r for r in routes if r.get("DestinationIpv6CidrBlock") == "2001:db8::/32"], (
        f"{label}: the refused IPv6 route must not have been installed anyway: {routes!r}"
    )
    v6_routes = [r for r in routes if r.get("DestinationIpv6CidrBlock") == "::/0"]
    assert len(v6_routes) == 1 and v6_routes[0].get("EgressOnlyInternetGatewayId") == eoigw, (
        f"{label}: expected one ::/0 route via {eoigw!r} in {rtb}, found {v6_routes!r}"
    )
    assert v6_routes[0].get("State") == "active", (
        f"{label}: the ::/0 route must be active before any traffic claim, got {v6_routes[0]!r}"
    )
    return {"vpc": vpc, "subnet": subnet, "eoigw": eoigw, "subnet_v6": subnet_v6, "rtb": rtb}


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


def _sole_ipv6(ec2, instance_id, subnet_v6):
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    enis = inst["NetworkInterfaces"]
    assert len(enis) == 1, f"expected exactly one ENI on {instance_id}, got {enis!r}"
    addrs = [a["Ipv6Address"] for a in enis[0].get("Ipv6Addresses", [])]
    assert len(addrs) == 1, (
        f"the subnet's AssignIpv6AddressOnCreation must give {instance_id} exactly one IPv6 "
        f"address, got {addrs!r}"
    )
    addr = ipaddress.IPv6Address(addrs[0])
    assert addr in subnet_v6, f"{addr!s} is outside its own subnet range {subnet_v6!s}"
    assert addr.is_global, (
        f"the address must be globally routable unicast for an inbound attempt to mean anything, "
        f"but {addr!s} is not (link_local={addr.is_link_local}, private={addr.is_private})"
    )
    return addr


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An egress-only internet gateway is one-way: a guest behind it reaches an IPv6 internet endpoint,
    while a guest in another VPC, admitted by the security group, cannot connect inbound to its global
    IPv6 address; the server reaching itself before and after pins the refusal on the gateway."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dipv6-egress-only-one-way"
    dual_stack_host = _DUAL_STACK_HOST_FMT.format(region=ctx.region)

    # --- everything decidable, before anything is created ---------------------
    az = _az_for(ec2, _WANT_TYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    profile = _instance_profile(ctx, iam, scenario)

    server_net = _dual_stack_egress_only_vpc(
        ctx, ec2, az, "10.181.0.0/16", "10.181.1.0/24", scenario, "server")
    client_net = _dual_stack_egress_only_vpc(
        ctx, ec2, az, "10.182.0.0/16", "10.182.1.0/24", scenario, "client")
    assert server_net["subnet_v6"] != client_net["subnet_v6"], (
        "the two Amazon-provided /56s collided, so the inbound attempt would be a same-prefix test: "
        f"{server_net['subnet_v6']!s} vs {client_net['subnet_v6']!s}"
    )

    def _sg(vpc, label, inbound):
        gid = ec2.create_security_group(
            GroupName=ctx.unique_name(f"sim2real-dipv6-{label}-"), VpcId=vpc,
            Description=f"sim2real-behav egress-only one-way {label}",
            TagSpecifications=[{"ResourceType": "security-group",
                                "Tags": [{"Key": "sim2real", "Value": scenario}]}])["GroupId"]
        ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=gid)))
        # The default egress rules follow the VPC's ADDRESS FAMILIES rather than being a fixed IPv4
        # default: a group created in a dual-stack VPC arrives with all-protocol egress for BOTH
        # 0.0.0.0/0 and ::/0. Measured; authorizing ::/0 egress explicitly here is refused as
        # InvalidPermission.Duplicate. Asserted rather than assumed because it decides whether the
        # inbound refusal below is attributable to the GATEWAY: if these groups did not already
        # permit IPv6 egress, no packet would leave the client regardless of the gateway.
        rules = []
        for page in ec2.get_paginator("describe_security_group_rules").paginate(
                Filters=[{"Name": "group-id", "Values": [gid]}]):
            rules += page["SecurityGroupRules"]
        egress = {(r.get("IpProtocol"), r.get("CidrIpv4") or r.get("CidrIpv6"))
                  for r in rules if r["IsEgress"]}
        assert egress == {("-1", "0.0.0.0/0"), ("-1", "::/0")}, (
            f"the {label} group must come with all-protocol egress for BOTH families, got "
            f"{sorted(egress)!r} in {gid}"
        )
        if inbound:
            ec2.authorize_security_group_ingress(
                GroupId=gid,
                IpPermissions=[{"IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
                                "Ipv6Ranges": [{"CidrIpv6": inbound}]}])
        return gid

    server_sg = _sg(server_net["vpc"], "srv", inbound=str(client_net["subnet_v6"]))
    client_sg = _sg(client_net["vpc"], "cli", inbound=None)

    # --- two instances, terminate registered immediately after each launch ----
    server_id = _launch(ctx, ec2, ami, server_net["subnet"], server_sg, profile, scenario, "server")
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, server_id))
    client_id = _launch(ctx, ec2, ami, client_net["subnet"], client_sg, profile, scenario, "client")
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, client_id))
    # Registered last so LIFO runs it first: both terminates are issued before either wait begins.
    ctx.on_cleanup(lambda: _terminate_nowait(ec2, [server_id, client_id]))

    for iid in (server_id, client_id):
        _poll(lambda i=iid: _instance_state(ec2, i), lambda s: s == "running",
              timeout_s=600, interval_s=5.0, what=f"instance {iid} reaching 'running'")
    server_addr = _sole_ipv6(ec2, server_id, server_net["subnet_v6"])
    client_addr = _sole_ipv6(ec2, client_id, client_net["subnet_v6"])
    for iid in (server_id, client_id):
        _wait_online(ssm, iid)

    # --- the security group provably admits the port over IPv6 ----------------
    rules = []
    for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [server_sg]}]):
        rules += page["SecurityGroupRules"]
    admitting = [r for r in rules
                 if not r["IsEgress"] and r.get("CidrIpv6") == str(client_net["subnet_v6"])
                 and r.get("FromPort") == _PORT and r.get("ToPort") == _PORT]
    assert len(admitting) == 1, (
        f"the server's security group must hold exactly one ingress rule from the client subnet for tcp/{_PORT} so "
        f"that it cannot be the thing refusing the connection; its rules are {rules!r}"
    )

    # --- the server: start the listener, prove it answers on its own address --
    self_url = f"http://[{server_addr!s}]:{_PORT}/"
    server_script = ["set -uo pipefail"] + _LISTENER + _PROBE_FUNC + [
        f"probe -6 '{self_url}' selfv6",
        f"probe -6 '{dual_stack_host}' server_outbound6",
    ]
    out = _run_guest(ssm, server_id, server_script, "starting the listener on the server")
    listener = _reports(out, "SIM2REAL-ID").get("listener")
    assert listener and listener["listen"] != "none", (
        f"the server never opened tcp/{_PORT}; `ss -ltn` showed nothing. stdout was {out!r}"
    )
    sp = _reports(out, "SIM2REAL-P")
    assert sp.get("selfv6", {}).get("code") == "200", (
        f"the server must be able to reach its OWN global IPv6 address on tcp/{_PORT}; without that "
        f"control a later inbound failure cannot be attributed to the gateway. Got "
        f"{sp.get('selfv6')!r}; stdout {out!r}"
    )
    assert sp.get("server_outbound6", {}).get("rc") == "0", (
        f"the server's own egress-only gateway must pass outbound-initiated IPv6, or its address is "
        f"not live on the internet at all: {sp.get('server_outbound6')!r}"
    )
    assert ":" in sp["server_outbound6"]["remote"], (
        f"the server's outbound leg did not travel over IPv6: {sp['server_outbound6']!r}"
    )

    # --- the client: outbound works, inbound to the server does NOT ----------
    client_script = ["set -uo pipefail"] + _PROBE_FUNC + [
        f"probe -6 '{dual_stack_host}' client_outbound6",
        f"probe -6 '{self_url}' inbound_try1",
        f"probe -6 '{self_url}' inbound_try2",
        f"probe -6 '{self_url}' inbound_try3",
    ]
    cout = _run_guest(ssm, client_id, client_script,
                      "probing the server's IPv6 address from the other VPC")
    cp = _reports(cout, "SIM2REAL-P")
    outbound = cp.get("client_outbound6")
    assert outbound and outbound["rc"] == "0" and outbound["code"] != "000", (
        f"the client's own egress-only gateway must pass outbound-initiated IPv6, otherwise its "
        f"failure to reach the server says nothing about the server's gateway: {outbound!r}; "
        f"stdout {cout!r}"
    )
    assert ":" in outbound["remote"], (
        f"the client's outbound control leg did not travel over IPv6: {outbound!r}"
    )

    attempts = [cp.get(f"inbound_try{n}") for n in (1, 2, 3)]
    assert all(attempts), f"the client did not report all three inbound attempts: {cout!r}"
    for n, a in enumerate(attempts, start=1):
        assert a["rc"] != "0", (
            f"attempt {n}: an egress-only internet gateway must not let another network OPEN a "
            f"connection to an instance behind it, but the client in {client_net['vpc']} "
            f"({client_addr!s}) reached {server_addr!s} on tcp/{_PORT} and got HTTP "
            f"{a['code']!r} from {a['remote']!r}. Its own outbound control was {outbound!r}"
        )
        assert a["code"] == "000", (
            f"attempt {n}: no HTTP status may come back from a refused inbound connection: {a!r}"
        )

    # --- the listener was alive throughout, so 'the server died' is excluded --
    after = _reports(_run_guest(ssm, server_id, ["set -uo pipefail"] + _PROBE_FUNC + [
        f"probe -6 '{self_url}' selfv6_after",
        f"L=$(ss -ltn 2>/dev/null | grep ':{_PORT}' | head -1 | tr -s ' ' ',')",
        "echo \"SIM2REAL-ID label=listener_after listen=${L:-none}\"",
    ], "re-checking the listener after the failed inbound attempts"), "SIM2REAL-P")
    assert after.get("selfv6_after", {}).get("code") == "200", (
        f"the server's listener must still answer on its own IPv6 address AFTER the client's "
        f"attempts, or the refusal above could have been the server dying rather than the gateway "
        f"blocking: {after.get('selfv6_after')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
