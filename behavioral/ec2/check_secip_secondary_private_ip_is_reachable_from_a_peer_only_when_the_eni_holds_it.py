"""secip-secondary-private-ip-is-reachable-from-a-peer-only-when-the-eni-holds-it."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secip-secondary-private-ip-is-reachable-from-a-peer-only-when-the-eni-holds-it"
GROUP = 'secondary-ip-data-plane'
SERVICES = ['ec2']

#: m5.large: a family that supports several ENIs and
#: several IPv4 addresses per ENI, which is the precondition for the behaviour; the AZ it runs in is
#: DERIVED, never named.
ITYPE = 'm5.large'
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_VPC_CIDR = "10.0.0.0/16"
_SUBNET_CIDR = "10.0.1.0/24"

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


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


def _retry_delete(fn, retries=36, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded: a DependencyViolation that never clears is a leak to declare, not a loop to sit in.
    """
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                              "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
                              "InvalidAssociationID.NotFound", "InvalidGroup.NotFound",
                              "InvalidNetworkInterfaceID.NotFound", "Gateway.NotAttached"):
                return None
            raise


def _usable_az(ec2, instance_type):
    """An AZ that is 'available' AND offers instance_type.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state, and
    describe_availability_zones says nothing about instance types. An empty intersection means this
    region cannot run the check at all.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ offers {instance_type!r} here; the offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _public_subnet(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with one public subnet in `az` and a self-referencing
    security group.

    Deliberately not the account's default VPC: a fresh account need not have one, and a shared
    default subnet would make the check assert a property of the account. The
    SSM agent needs egress to reach its endpoint, so the subnet gets an internet gateway, a default
    route and auto-assigned public addressing. The security group permits every protocol FROM ITSELF,
    which is what lets one instance in the subnet probe another without opening anything to the
    internet. Every piece is tagged at creation — an untagged VPC object cannot be found for
    cleanup.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR,
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    rtb = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=tagspec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rtb)))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-secip-")[:255], VpcId=vpc,
        Description="sim2real-behav secondary-ip data plane",
        TagSpecifications=tagspec("security-group"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=sg)))
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg}]}])
    return subnet, sg


def _instance_profile(ctx, iam, scenario):
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-secip-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav secondary-ip data-plane role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    # IAM has no API that reports a role as effective, so RunInstances is retried on the
    # InvalidParameterValue a not-yet-resolvable instance profile produces (see _launch).
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


def _terminate_and_wait(ec2, instance_ids, timeout_s=700):
    """Terminate every instance FIRST, then wait for all of them.

    One net for the whole set rather than one per instance: the cleanup chain is bounded from
    outside, so issuing all the terminates before any wait makes teardown cost the MAX rather than
    the SUM. Waiting for 'terminated' (not merely 'shutting-down') is required because the ENIs and
    the instance-profile association only clear at the end, and the subnet/SG/VPC teardown
    registered earlier cannot proceed until they do.
    """
    for instance_id in instance_ids:
        try:
            _call_with_retry(lambda i=instance_id: ec2.terminate_instances(InstanceIds=[i]))
        except ClientError as exc:
            if _code(exc) != "InvalidInstanceID.NotFound":
                raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if all(_instance_state(ec2, i) in ("terminated", "__gone__") for i in instance_ids):
            return
        time.sleep(5)


def _launch(ctx, ec2, *, ami, subnet, sg, profile, count, scenario):
    tag_spec = [
        {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": profile},
                                      {"Key": "sim2real", "Value": scenario}]}
        for rt in ("instance", "volume", "network-interface")
    ]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=ITYPE, MinCount=count, MaxCount=count, SubnetId=subnet,
            SecurityGroupIds=[sg], IamInstanceProfile={"Name": profile},
            TagSpecifications=tag_spec),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    ids = [i["InstanceId"] for i in resv["Instances"]]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, ids))
    return ids


def _primary_eni(ec2, instance_id):
    """The instance's device-index-0 network interface, from a PAGINATED DescribeInstances."""
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] != instance_id:
                    continue
                for eni in inst["NetworkInterfaces"]:
                    if eni["Attachment"]["DeviceIndex"] == 0:
                        return eni
    raise AssertionError(
        f"instance {instance_id} has no device-index-0 network interface in any page of "
        f"DescribeInstances"
    )


def _wait_ssm_online(ssm, instance_ids, timeout_s=600):
    """Every instance's SSM agent reaches PingStatus Online.

    A host that never registers is a FAIL, not an environment limitation: 'the machine did not come
    up' is the fidelity defect this check exists to catch.
    """
    def _statuses():
        seen = {}
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") in instance_ids:
                    seen[info["InstanceId"]] = info.get("PingStatus")
        return {i: seen.get(i) for i in instance_ids}

    return _poll(_statuses, lambda s: all(v == "Online" for v in s.values()),
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"the SSM agents on {instance_ids!r} coming Online")


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=300):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted rejects SendCommand
    with InvalidInstanceId until its agent has registered, so retrying that call polls an observable
    condition instead of sleeping a guessed interval.
    """
    deadline = time.monotonic() + ready_timeout_s
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                Parameters={"commands": script}, TimeoutSeconds=600,
                Comment="sim2real-behav secondary-ip data plane")
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


def _report(stdout, marker):
    """The `key=value` fields of the last line starting with `marker`, as a dict."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith(marker):
            continue
        out = {}
        for field in line[len(marker):].split():
            if "=" in field:
                k, _, v = field.partition("=")
                out[k] = v
        return out
    return None


def _csv(value):
    """A comma-joined guest field as a set, with the empty markers dropped."""
    return {p for p in (value or "").split(",") if p and p != "none"}


#: IMDSv2 preamble. AL2023 defaults to HttpTokens=required, so every metadata read needs a token;
#: this is the instance talking to the hypervisor's own service, not an AWS API call.
_IMDS = (
    'T=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" '
    '-H "X-aws-ec2-metadata-token-ttl-seconds: 180")\n'
    'md() { curl -s -H "X-aws-ec2-metadata-token: $T" '
    '"http://169.254.169.254/latest/meta-data/$1"; }\n'
)


def _iface_by_mac(mac):
    """Shell that resolves a MAC to its kernel interface name.

    By MAC, never by name: `ens5`/`eth0` is a udev naming policy, and the device-number ordering is
    not the attachment order.
    """
    return (
        'IF=""\n'
        'for d in /sys/class/net/*; do\n'
        f'  [ "$(cat $d/address 2>/dev/null)" = "{mac}" ] && IF=${{d##*/}}\n'
        'done\n'
    )


def _free_subnet_address(ec2, subnet_id, cidr):
    """An address inside `cidr` that no ENI in `subnet_id` holds.

    Read from a PAGINATED DescribeNetworkInterfaces filtered to this check's OWN subnet, so
    'nobody holds it' is a property of the query rather than of who else is running in the account.
    The first four host addresses are skipped because AWS reserves them in every subnet.
    """
    held = set()
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]):
        for eni in page["NetworkInterfaces"]:
            for addr in eni["PrivateIpAddresses"]:
                held.add(addr["PrivateIpAddress"])
    candidates = [str(h) for h in list(ipaddress.ip_network(cidr).hosts())[4:]
                  if str(h) not in held]
    assert candidates, (
        f"subnet {subnet_id} ({cidr}) has no unheld host address; its ENIs hold {sorted(held)!r}"
    )
    return candidates[-1], held


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "dp:native", "plane:data")
def run(ctx) -> None:
    """A peer instance reaches a secondary private IP only when the target's ENI holds it: with both
    addresses configured in the guest, the one AssignPrivateIpAddresses granted answers ICMP and appears
    in IMDS, and the unassigned one is dark and absent."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "secip-peer-reachability"

    az = _usable_az(ec2, ITYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 x86_64 parameter did not resolve to an AMI: {ami!r}"

    subnet, sg = _public_subnet(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)
    target, peer = _launch(ctx, ec2, ami=ami, subnet=subnet, sg=sg, profile=profile, count=2,
                           scenario=scenario)

    _poll(lambda: [_instance_state(ec2, target), _instance_state(ec2, peer)],
          lambda s: all(x == "running" for x in s), timeout_s=600, interval_s=5.0,
          what=f"instances {target} and {peer} reaching 'running'")
    eni = _primary_eni(ec2, target)
    eni_id, primary_ip, mac = eni["NetworkInterfaceId"], eni["PrivateIpAddress"], eni["MacAddress"]
    _wait_ssm_online(ssm, [target, peer])

    # --- one address EC2 granted, one address it did not ----------------------
    granted = ec2.assign_private_ip_addresses(
        NetworkInterfaceId=eni_id,
        SecondaryPrivateIpAddressCount=1)["AssignedPrivateIpAddresses"][0]["PrivateIpAddress"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.unassign_private_ip_addresses(
        NetworkInterfaceId=eni_id, PrivateIpAddresses=[granted])))
    ungranted, held = _free_subnet_address(ec2, subnet, _SUBNET_CIDR)
    assert granted in held, (
        f"the address {granted!r} AssignPrivateIpAddresses just granted is not among the addresses "
        f"the subnet's ENIs hold ({sorted(held)!r}) — the assignment was not recorded at all"
    )
    prefix = ipaddress.ip_network(_SUBNET_CIDR).prefixlen

    # --- the guest configures BOTH, so kernel state is held constant -----------
    configure = [
        "set -euo pipefail",
        _iface_by_mac(mac),
        'if [ -z "$IF" ]; then echo "SIM2REAL-CFG iface=none"; ip -o link show; exit 1; fi',
        f'ip addr add {granted}/{prefix} dev "$IF"',
        f'ip addr add {ungranted}/{prefix} dev "$IF"',
        'echo "SIM2REAL-CFG iface=$IF"',
    ]
    cfg = _report(_run_guest(ssm, target, configure,
                             "the target configures both addresses on its primary interface"),
                  "SIM2REAL-CFG")
    assert cfg and cfg.get("iface") not in (None, "none"), (
        f"the guest could not resolve its primary interface from MAC {mac!r}; it reported {cfg!r}"
    )
    iface = cfg["iface"]

    read = [
        "set -uo pipefail",
        _IMDS,
        _iface_by_mac(mac),
        'ADDRS=$(ip -4 -o addr show dev "$IF" | awk \'{print $4}\' | cut -d/ -f1 | tr \'\\n\' \',\')',
        f'IMDS=$(md network/interfaces/macs/{mac}/local-ipv4s | tr \'\\n\' \',\')',
        'echo "SIM2REAL-ADDRS iface=$IF kernel=$ADDRS imds=$IMDS"',
    ]
    view = _report(
        _poll(lambda: _run_guest(ssm, target, read, "the target reports its own addresses"),
              lambda o: granted in _csv((_report(o, "SIM2REAL-ADDRS") or {}).get("imds")),
              timeout_s=240, interval_s=15.0,
              what=f"the target's own IMDS listing {granted} under MAC {mac}"),
        "SIM2REAL-ADDRS")
    kernel, imds = _csv(view.get("kernel")), _csv(view.get("imds"))

    assert {primary_ip, granted, ungranted} <= kernel, (
        f"the guest kernel must carry all three addresses on {iface!r} before the comparison means "
        f"anything — it reported {sorted(kernel)!r}, expected to include "
        f"{sorted({primary_ip, granted, ungranted})!r}"
    )
    assert imds == {primary_ip, granted}, (
        f"the instance's own metadata must list exactly the addresses EC2 assigned to "
        f"{eni_id} — {sorted({primary_ip, granted})!r} — but the guest read "
        f"{sorted(imds)!r}; {ungranted!r} was configured in the kernel and must NOT appear"
    )

    # --- the witness is a second machine on the wire --------------------------
    probe = [
        "set -uo pipefail",
        f"ping -c 3 -W 2 {primary_ip} >/dev/null 2>&1 && P=reachable || P=dark",
        f"ping -c 3 -W 2 {granted} >/dev/null 2>&1 && G=reachable || G=dark",
        f"ping -c 3 -W 2 {ungranted} >/dev/null 2>&1 && U=reachable || U=dark",
        'echo "SIM2REAL-PING primary=$P granted=$G ungranted=$U"',
    ]
    pings = _report(
        _poll(lambda: _run_guest(ssm, peer, probe, "the peer probes the target's three addresses"),
              lambda o: (_report(o, "SIM2REAL-PING") or {}).get("granted") == "reachable",
              timeout_s=240, interval_s=20.0,
              what=f"the peer reaching the target on the granted secondary address {granted}"),
        "SIM2REAL-PING")

    assert pings["primary"] == "reachable", (
        f"the peer could not reach the target on its PRIMARY address {primary_ip} "
        f"({pings['primary']!r}) — the subnet path itself is broken, so nothing else here is "
        f"interpretable; the guest reported {pings!r}"
    )
    assert pings["granted"] == "reachable", (
        f"the peer must reach the target on the secondary address {granted} that "
        f"AssignPrivateIpAddresses granted to {eni_id} and the guest has configured on {iface!r}, "
        f"but it was {pings['granted']!r}; the guest reported {pings!r}"
    )
    assert pings["ungranted"] == "dark", (
        f"the address {ungranted} is configured on the SAME interface by the SAME kernel but was "
        f"never assigned to {eni_id}, so the VPC must not deliver to it — the peer found it "
        f"{pings['ungranted']!r}. An emulator reaching this address is forwarding on guest "
        f"configuration rather than on the ENI's assignment; the guest reported {pings!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
