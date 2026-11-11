"""dipv6-guest-ipv6-egress-flows-through-the-egress-only-gateway-and-stops-when-its-route-is-removed."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dipv6-guest-ipv6-egress-flows-through-the-egress-only-gateway-and-stops-when-its-route-is-removed"
GROUP = 'ipv6-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_WANT_TYPE = "t3.micro"
#: The guest's IPv6 destination. AWS publishes a dual-stack endpoint for every service under
#: `<service>.<region>.api.aws`, which has a AAAA record and a globally routable address, so the
#: destination is DERIVED from ctx.region rather than hardcoded and belongs to AWS rather than to a
#: third party. A plain GET is answered with an HTTP error code, which is all this needs: any
#: status line at all proves a TCP handshake plus a TLS handshake plus an HTTP round trip
#: completed end to end over IPv6.
_DUAL_STACK_HOST_FMT = "https://dynamodb.{region}.api.aws/"

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
                    Description="sim2real-behav dual-stack ipv6 data-plane role",
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
                Comment="sim2real-behav ipv6 egress-only data plane",
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
    """Every `key=value` line starting with *marker*, keyed by its *key* field.

    The guest emits one machine-readable line per probe, so nothing here depends on the order or
    the wording of the rest of its output.
    """
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


#: A shell function that measures one HTTP request and reports it as a parseable line. It NEVER
#: fails the script: the guest is a measuring instrument and the check does the asserting, so a
#: refused connection has to come back as data (`rc`, `code`, `remote`) rather than as a non-zero
#: exit that `_run_guest` would read as a broken script. `%{remote_ip}` is the load-bearing field —
#: it is the peer address the kernel actually connected to, which is the only way to prove from
#: inside the guest that the bytes travelled over IPv6 and not over a happy-eyeballs IPv4 fallback.
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


def _both_probes(host, label6, label4):
    """Probe *host* over IPv6 and then over IPv4, in one guest invocation.

    Same script, same host, same moment — the IPv4 leg is the positive control that says the guest,
    its DNS and the destination are all still healthy when the IPv6 leg reports a failure.
    """
    return ["set -uo pipefail"] + _PROBE_FUNC + [
        f"probe -6 '{host}' {label6}",
        f"probe -4 '{host}' {label4}",
    ]


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A dual-stack guest with a global IPv6 address reaches an IPv6 destination through an egress-only
    internet gateway; deleting the ::/0 route stops IPv6 while IPv4 keeps flowing, and restoring it
    brings IPv6 back."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dipv6-egress-only-route"
    dual_stack_host = _DUAL_STACK_HOST_FMT.format(region=ctx.region)

    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario},
                                              {"Key": "Name", "Value": scenario}]}]

    # --- everything decidable, before anything is created ---------------------
    az = _az_for(ec2, _WANT_TYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    # --- a dual-stack VPC of this check's own making --------------------------
    # Deliberately not the account's default VPC: a fresh account need not have one, and a shared
    # default subnet would make the check assert a property of the account.
    vpc = ec2.create_vpc(CidrBlock="10.180.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
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
    assert vpc_v6_net.prefixlen == 56, (
        f"an Amazon-provided VPC IPv6 CIDR is a /56, got {v6['Ipv6CidrBlock']!r}"
    )
    subnet_v6 = next(vpc_v6_net.subnets(new_prefix=64))

    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))

    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.180.1.0/24",
                               Ipv6CidrBlock=str(subnet_v6), AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    # IPv4 public addressing is what lets the SSM agent reach its endpoint; IPv6 auto-assignment is
    # the subject. Both are subnet attributes rather than RunInstances arguments on purpose, so the
    # check grades the subnet's own behaviour.
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

    # A route table holds at most one entry per destination, and CreateRoute reaches that state
    # IDEMPOTENTLY rather than by refusing: re-issuing the identical destination-and-target pair
    # returns Return=true. It is NOT RouteAlreadyExists, which is what the IPv4-era wording leads
    # you to expect, so an emulator is as likely to be wrong by rejecting the repeat as by
    # appending a second ::/0 entry. Both are pinned here.
    again = ec2.create_route(RouteTableId=rtb, DestinationIpv6CidrBlock="::/0",
                             EgressOnlyInternetGatewayId=eoigw)
    assert again.get("Return") is True, (
        f"re-creating the identical ::/0 -> {eoigw} route must be idempotent, got {again!r}"
    )

    installed = [r for r in ec2.describe_route_tables(RouteTableIds=[rtb])["RouteTables"][0]["Routes"]
                 if r.get("DestinationIpv6CidrBlock") == "::/0"]
    assert len(installed) == 1 and installed[0].get("EgressOnlyInternetGatewayId") == eoigw, (
        f"exactly one ::/0 route via {eoigw!r} must exist in {rtb}, found {installed!r}"
    )
    assert installed[0].get("State") == "active", (
        f"the ::/0 route must be active before any traffic claim, got {installed[0]!r}"
    )

    # --- a security group that permits IPv6 egress ----------------------------
    # The default egress rules follow the VPC's ADDRESS FAMILIES, not a fixed IPv4 default: a group
    # created in a dual-stack VPC comes with TWO all-protocol egress rules, 0.0.0.0/0 and ::/0.
    # An explicit authorize of ::/0 here is refused as InvalidPermission.Duplicate. This is
    # asserted rather than assumed because it is precisely what
    # decides whether the absent leg below is attributable: if the group did NOT permit ::/0 egress,
    # the check would be measuring its own security group instead of the gateway.
    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-dipv6-sg-"), VpcId=vpc,
        Description="sim2real-behav dual-stack egress",
        TagSpecifications=tagspec("security-group"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg)))
    sg_rules = []
    for page in ec2.get_paginator("describe_security_group_rules").paginate(
            Filters=[{"Name": "group-id", "Values": [sg]}]):
        sg_rules += page["SecurityGroupRules"]
    default_egress = {(r.get("IpProtocol"), r.get("CidrIpv4") or r.get("CidrIpv6"))
                      for r in sg_rules if r["IsEgress"]}
    assert default_egress == {("-1", "0.0.0.0/0"), ("-1", "::/0")}, (
        f"a group created in a dual-stack VPC must come with all-protocol egress for BOTH families, "
        f"got {sorted(default_egress)!r} in {sg}"
    )
    assert not [r for r in sg_rules if not r["IsEgress"]], (
        f"a new group must have no ingress rules at all, got {sg_rules!r}"
    )

    profile = _instance_profile(ctx, iam, scenario)

    # --- one dual-stack instance ----------------------------------------------
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_WANT_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet, SecurityGroupIds=[sg],
            IamInstanceProfile={"Name": profile},
            TagSpecifications=tagspec("instance") + tagspec("volume"),
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {az!r}"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")

    # --- view 1: the control plane's record of the ENI's IPv6 address ---------
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    enis = inst["NetworkInterfaces"]
    assert len(enis) == 1, f"expected exactly one ENI on {instance_id}, got {enis!r}"
    cp_v6 = [a["Ipv6Address"] for a in enis[0].get("Ipv6Addresses", [])]
    assert len(cp_v6) == 1, (
        f"AssignIpv6AddressOnCreation on {subnet} must give the launched instance exactly one IPv6 "
        f"address, but DescribeInstances reported {cp_v6!r} for {instance_id}"
    )
    control_plane_addr = ipaddress.IPv6Address(cp_v6[0])
    assert control_plane_addr in subnet_v6, (
        f"the assigned address {control_plane_addr!s} is outside the subnet's own range "
        f"{subnet_v6!s}"
    )
    assert control_plane_addr.is_global, (
        f"the address must be globally routable unicast, but {control_plane_addr!s} is not "
        f"(link_local={control_plane_addr.is_link_local}, private={control_plane_addr.is_private})"
    )

    # --- the agent must register: a host that never registers is a FAIL -------
    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=600, interval_s=5.0,
                 what=f"the SSM agent on {instance_id} coming Online")
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )

    # --- views 2 and 3, plus the baseline traffic, from inside the guest ------
    identity = ["set -uo pipefail",
                "A=none",
                "for i in $(seq 1 45); do",
                "  A=$(ip -6 -o addr show scope global 2>/dev/null | "
                "awk '{print $4}' | cut -d/ -f1 | head -1)",
                "  if [ -n \"$A\" ]; then break; fi",
                "  A=none; sleep 2",
                "done",
                "T=$(curl -sS --max-time 10 -X PUT "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 300' "
                "http://169.254.169.254/latest/api/token 2>/dev/null)",
                "MAC=$(curl -sS --max-time 10 -H \"X-aws-ec2-metadata-token: $T\" "
                "http://169.254.169.254/latest/meta-data/mac 2>/dev/null)",
                "IM=$(curl -sS --max-time 10 -H \"X-aws-ec2-metadata-token: $T\" "
                "\"http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/ipv6s\" "
                "2>/dev/null | head -1)",
                "DEF=$(ip -6 route show default 2>/dev/null | head -1 | tr ' ' ',')",
                "echo \"SIM2REAL-ID label=identity kernel=${A:-none} imds=${IM:-none} "
                "defroute=${DEF:-none}\"",
                ] + _PROBE_FUNC + [
                f"probe -6 '{dual_stack_host}' baseline6",
                f"probe -4 '{dual_stack_host}' baseline4",
    ]
    out = _run_guest(ssm, instance_id, identity, "reading the guest's IPv6 identity and egress")
    ident = _reports(out, "SIM2REAL-ID").get("identity")
    assert ident, f"the guest did not report its IPv6 identity; its stdout was {out!r}"
    assert ident["kernel"] == str(control_plane_addr), (
        f"the kernel inside the guest holds {ident['kernel']!r} as its global IPv6 address, but "
        f"the control plane recorded {control_plane_addr!s} on the ENI; guest said {ident!r}"
    )
    assert ident["imds"] == str(control_plane_addr), (
        f"IMDS served {ident['imds']!r} as the interface's IPv6 address, but the control plane "
        f"recorded {control_plane_addr!s}; guest said {ident!r}"
    )
    assert ident["defroute"] != "none", (
        f"a dual-stack guest must hold an IPv6 default route for the ::/0 entry to be usable, but "
        f"`ip -6 route show default` was empty; guest said {ident!r}"
    )

    probes = _reports(out, "SIM2REAL-P")
    base6 = probes.get("baseline6")
    base4 = probes.get("baseline4")
    assert base6 and base4, f"the guest did not report both baseline probes; stdout was {out!r}"
    assert base6["rc"] == "0", (
        f"with a ::/0 route to egress-only gateway {eoigw} and a ::/0 egress rule, the guest must "
        f"reach {dual_stack_host} over IPv6, but curl exited {base6['rc']!r} "
        f"(code={base6['code']!r}); the IPv4 control reported {base4!r}. Guest stdout: {out!r}"
    )
    assert base6["code"] != "000", (
        f"no HTTP status came back over IPv6, so no round trip completed: {base6!r}"
    )
    assert ":" in base6["remote"], (
        f"the peer the guest connected to must be an IPv6 address for this to be IPv6 egress, but "
        f"curl reported remote={base6['remote']!r}"
    )
    assert base4["rc"] == "0" and base4["code"] != "000", (
        f"the IPv4 control leg must succeed so that a later IPv6 failure is attributable to IPv6: "
        f"{base4!r}"
    )
    assert ":" not in base4["remote"], (
        f"the -4 leg must have connected over IPv4, got remote={base4['remote']!r}"
    )

    # --- the absent leg: break exactly ONE thing, the ::/0 route --------------
    ec2.delete_route(RouteTableId=rtb, DestinationIpv6CidrBlock="::/0")
    remaining = [r for r in ec2.describe_route_tables(RouteTableIds=[rtb])["RouteTables"][0]["Routes"]
                 if r.get("DestinationIpv6CidrBlock") == "::/0"]
    assert not remaining, f"the ::/0 route is still present after DeleteRoute: {remaining!r}"
    # The exact-code negative, with the delete that just succeeded as its positive control: the
    # route is genuinely gone, so a second DeleteRoute has nothing to remove. Attributable by
    # construction — this check created the table and knows it holds no ::/0 entry.
    code, message = _error(lambda: ec2.delete_route(RouteTableId=rtb,
                                                    DestinationIpv6CidrBlock="::/0"))
    assert code == "InvalidRoute.NotFound", (
        f"deleting the already-deleted ::/0 route in {rtb} must be refused with "
        f"InvalidRoute.NotFound, got {code!r}"
    )
    assert message == f"no route with destination-cidr-block ::/0 in route table {rtb}", message
    # The gateway itself is untouched, which is the point: only the route is gone.
    gws = ec2.describe_egress_only_internet_gateways(
        EgressOnlyInternetGatewayIds=[eoigw])["EgressOnlyInternetGateways"]
    assert gws and gws[0]["Attachments"][0]["VpcId"] == vpc, (
        f"the egress-only gateway must still be attached to {vpc} after the route was deleted, "
        f"got {gws!r}"
    )

    broken = _poll(
        lambda: _reports(_run_guest(ssm, instance_id,
                                    _both_probes(dual_stack_host, "broken6", "broken4"),
                                    "probing after the ::/0 route was deleted"), "SIM2REAL-P"),
        lambda p: p.get("broken6", {}).get("rc") not in (None, "0"),
        timeout_s=300, interval_s=5.0,
        what=f"IPv6 egress from {instance_id} ceasing after the ::/0 route was deleted")
    assert broken["broken6"]["code"] == "000", (
        f"with no ::/0 route the IPv6 request must not complete, but the guest still got HTTP "
        f"{broken['broken6']['code']!r} from {broken['broken6']['remote']!r}"
    )
    assert broken["broken4"]["rc"] == "0" and broken["broken4"]["code"] != "000", (
        f"deleting the IPv6 route must not disturb IPv4: the control leg to the same host reported "
        f"{broken['broken4']!r}, so the IPv6 failure above cannot be attributed to IPv6 routing"
    )

    # --- restore it: IPv6 comes back, so the removal was the cause ------------
    ec2.create_route(RouteTableId=rtb, DestinationIpv6CidrBlock="::/0",
                     EgressOnlyInternetGatewayId=eoigw)
    restored = _poll(
        lambda: _reports(_run_guest(ssm, instance_id,
                                    _both_probes(dual_stack_host, "restored6", "restored4"),
                                    "probing after the ::/0 route was restored"), "SIM2REAL-P"),
        lambda p: p.get("restored6", {}).get("rc") == "0",
        timeout_s=300, interval_s=5.0,
        what=f"IPv6 egress from {instance_id} resuming once the ::/0 route was restored")
    assert ":" in restored["restored6"]["remote"], (
        f"IPv6 egress resumed but over the wrong family: remote="
        f"{restored['restored6']['remote']!r}"
    )
    assert restored["restored6"]["code"] != "000", (
        f"the restored IPv6 leg reported no HTTP status: {restored['restored6']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
