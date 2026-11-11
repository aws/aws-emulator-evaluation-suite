"""secip-assigning-more-private-ips-than-the-instance-type-permits-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secip-assigning-more-private-ips-than-the-instance-type-permits-rejected"
GROUP = 'secondary-ip-rejected'
SERVICES = ['ec2']

#: m5.large. The limit is never hard-coded: Ipv4AddressesPerInterface is read from
#: DescribeInstanceTypes for the launched type.
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

    Deliberately not the account's default VPC: an account need not have one, and a shared default
    subnet would make the check assert a property of the account. The
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


def _error_code(fn, *, undo=None):
    """The AWS error (code, message) `fn` raised.

    An unexpected SUCCESS is NOT a code and must never be returned as a falsy sentinel: an emulator
    that accepts input real AWS refuses is the strongest signal this check can produce, so it is
    raised as itself rather than degraded into an error-code mismatch. The resource the wrongly
    successful call created is undone first, because a bare failure here would leak it.
    """
    try:
        resp = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    if undo is not None:
        undo(resp)
    raise AssertionError(
        f"the call was expected to be REJECTED but it SUCCEEDED, returning {resp!r} — accepting "
        f"input real AWS refuses is over-permissiveness, the failure mode this check exists to catch"
    )


def _eni_addresses(ec2, eni_id):
    """Every private IPv4 address the ENI holds, from a PAGINATED DescribeNetworkInterfaces."""
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            NetworkInterfaceIds=[eni_id]):
        for eni in page["NetworkInterfaces"]:
            if eni["NetworkInterfaceId"] == eni_id:
                return {a["PrivateIpAddress"] for a in eni["PrivateIpAddresses"]}
    raise AssertionError(f"{eni_id} not found in any page of DescribeNetworkInterfaces")


def _guest_addresses(ssm, instance_id, mac, what):
    """The addresses the INSTANCE ITSELF reports for `mac`, read from IMDS inside the guest."""
    script = [
        "set -uo pipefail",
        _IMDS,
        f'IPS=$(md network/interfaces/macs/{mac}/local-ipv4s | tr \'\\n\' \',\')',
        'echo "SIM2REAL-IPS imds=$IPS"',
    ]
    out = _run_guest(ssm, instance_id, script, what)
    rep = _report(out, "SIM2REAL-IPS")
    assert rep is not None, f"{what}: the guest printed no SIM2REAL-IPS line; stdout was {out!r}"
    return _csv(rep.get("imds"))

# ===== end helpers =====

@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Filling a running instance's primary ENI to the IPv4 limit DescribeInstanceTypes declares succeeds and
    is visible in the guest's IMDS, and one more is refused PrivateIpAddressLimitExceeded with no address
    added, in the control plane or in the guest."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "secip-ip-limit-rejected"

    catalog = []
    for page in ec2.get_paginator("describe_instance_types").paginate(InstanceTypes=[ITYPE]):
        catalog += page["InstanceTypes"]
    assert len(catalog) == 1, (
        f"DescribeInstanceTypes({ITYPE!r}) returned {len(catalog)} entries: {catalog!r}"
    )
    limit = catalog[0]["NetworkInfo"]["Ipv4AddressesPerInterface"]
    assert limit > 1, (
        f"{ITYPE} declares Ipv4AddressesPerInterface={limit}, so there is no secondary address to "
        f"assign and the positive control would be vacuous"
    )

    az = _usable_az(ec2, ITYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 x86_64 parameter did not resolve to an AMI: {ami!r}"

    subnet, sg = _public_subnet(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)
    (target,) = _launch(ctx, ec2, ami=ami, subnet=subnet, sg=sg, profile=profile, count=1,
                        scenario=scenario)
    _poll(lambda: _instance_state(ec2, target), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {target} reaching 'running'")
    eni = _primary_eni(ec2, target)
    eni_id, primary_ip, mac = eni["NetworkInterfaceId"], eni["PrivateIpAddress"], eni["MacAddress"]
    _wait_ssm_online(ssm, [target])

    assert _eni_addresses(ec2, eni_id) == {primary_ip}, (
        f"a freshly launched interface must hold only its primary address {primary_ip!r}, but "
        f"{eni_id} holds {sorted(_eni_addresses(ec2, eni_id))!r}"
    )

    # --- positive control: fill the interface to EXACTLY the declared limit -----
    filled = ec2.assign_private_ip_addresses(
        NetworkInterfaceId=eni_id, SecondaryPrivateIpAddressCount=limit - 1)
    secondaries = {a["PrivateIpAddress"] for a in filled["AssignedPrivateIpAddresses"]}
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.unassign_private_ip_addresses(
        NetworkInterfaceId=eni_id, PrivateIpAddresses=sorted(secondaries))))
    assert len(secondaries) == limit - 1, (
        f"asking for {limit - 1} secondary addresses returned {len(secondaries)}: "
        f"{sorted(secondaries)!r}"
    )
    at_limit = _eni_addresses(ec2, eni_id)
    assert at_limit == {primary_ip} | secondaries, (
        f"after filling the interface it must hold its primary plus every granted secondary "
        f"({sorted({primary_ip} | secondaries)!r}), but DescribeNetworkInterfaces reports "
        f"{sorted(at_limit)!r}"
    )
    assert len(at_limit) == limit, (
        f"{eni_id} holds {len(at_limit)} addresses, expected exactly the declared limit {limit}: "
        f"{sorted(at_limit)!r}"
    )

    # --- and the MACHINE ITSELF must be holding them, not just the record -------
    in_guest = _poll(
        lambda: _guest_addresses(ssm, target, mac, "the guest reports its own addresses"),
        lambda s: s == at_limit, timeout_s=300, interval_s=15.0,
        what=f"the instance's own metadata listing all {limit} addresses under MAC {mac}")
    assert in_guest == at_limit, (
        f"the instance's own metadata service must list exactly the {limit} addresses assigned to "
        f"{eni_id} — {sorted(at_limit)!r} — but the guest read {sorted(in_guest)!r}"
    )

    # --- break exactly one thing: ask for ONE more than the type permits --------
    def _undo(resp):
        extra = [a["PrivateIpAddress"] for a in resp.get("AssignedPrivateIpAddresses", [])]
        if extra:
            ec2.unassign_private_ip_addresses(NetworkInterfaceId=eni_id, PrivateIpAddresses=extra)

    code, message = _error_code(
        lambda: ec2.assign_private_ip_addresses(NetworkInterfaceId=eni_id,
                                                SecondaryPrivateIpAddressCount=1),
        undo=_undo)
    assert code == "PrivateIpAddressLimitExceeded", (
        f"assigning a {limit + 1}th private address to {eni_id} on a {ITYPE} — whose declared "
        f"Ipv4AddressesPerInterface is {limit} — must be refused PrivateIpAddressLimitExceeded, but "
        f"real AWS's code was {code!r}"
    )
    assert message == "Number of private addresses will exceed limit.", message

    # --- the effect is ABSENT: nothing was added, on either side of the boundary -
    after = _eni_addresses(ec2, eni_id)
    assert after == at_limit, (
        f"the refused assignment must leave the interface exactly as it was "
        f"({sorted(at_limit)!r}), but {eni_id} now holds {sorted(after)!r} — a rejection that still "
        f"mutates state is worse than an acceptance"
    )
    after_in_guest = _guest_addresses(ssm, target, mac,
                                      "the guest reports its addresses after the refusal")
    assert after_in_guest == at_limit, (
        f"the machine's own view must be unchanged by the refused call ({sorted(at_limit)!r}), but "
        f"the guest read {sorted(after_in_guest)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
