"""secip-hot-attached-second-eni-appears-in-the-guest-as-a-new-interface-with-its-own-address."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secip-hot-attached-second-eni-appears-in-the-guest-as-a-new-interface-with-its-own-address"
GROUP = 'secondary-ip-data-plane'
SERVICES = ['ec2']

# Must support more than one ENI; run() asserts MaximumNetworkInterfaces before creating anything.
ITYPE = 'm5.large'
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_VPC_CIDR = "10.0.0.0/16"
_SUBNET_CIDR = "10.0.1.0/24"
#: The hot-attach lands at device index 1: index 0 is the primary interface RunInstances created.
_DEVICE_INDEX = 1

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


def _bounded(ctx, cap_s, reserve_s=10.0):
    """`cap_s`, shortened so the wait ends `reserve_s` before the runner stops the check."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


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
    """Delete, retrying (bounded) through the dependency window a just-terminated ENI leaves."""
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
    """An AZ that is both available and offers instance_type; neither API reports both."""
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
    """A new VPC with one public subnet in `az` and a self-referencing security group.

    The SSM agent needs egress, hence the internet gateway, default route and public addressing.
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
    """Terminate every instance, then wait for 'terminated': ENIs and the instance-profile
    association only clear then, and the subnet/SG/VPC teardown depends on that."""
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
    """The instance's device-index-0 network interface, from a paginated DescribeInstances."""
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


def _wait_ssm_online(ctx, ssm, instance_ids, timeout_s=600):
    """Wait until every instance's SSM agent reports PingStatus Online."""
    def _statuses():
        seen = {}
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") in instance_ids:
                    seen[info["InstanceId"]] = info.get("PingStatus")
        return {i: seen.get(i) for i in instance_ids}

    return _poll(_statuses, lambda s: all(v == "Online" for v in s.values()),
                 timeout_s=_bounded(ctx, timeout_s), interval_s=2.0,
                 what=f"the SSM agents on {instance_ids!r} coming Online")


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=300):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand fails with InvalidInstanceId until the agent registers, so retrying it is the wait.
    """
    deadline = time.monotonic() + _bounded(ctx, ready_timeout_s)
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                Parameters={"commands": script}, TimeoutSeconds=600,
                Comment="sim2real-behav secondary-ip data plane")
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(2)
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
                timeout_s=_bounded(ctx, run_timeout_s), interval_s=2.0,
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


# IMDSv2 preamble: AL2023 defaults to HttpTokens=required, so every metadata read needs a token.
_IMDS = (
    'T=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" '
    '-H "X-aws-ec2-metadata-token-ttl-seconds: 180")\n'
    'md() { curl -s -H "X-aws-ec2-metadata-token: $T" '
    '"http://169.254.169.254/latest/meta-data/$1"; }\n'
)


def _iface_by_mac(mac):
    """Shell that resolves a MAC to its kernel interface name; names and device order do not
    follow the attachment order."""
    return (
        'IF=""\n'
        'for d in /sys/class/net/*; do\n'
        f'  [ "$(cat $d/address 2>/dev/null)" = "{mac}" ] && IF=${{d##*/}}\n'
        'done\n'
    )


def _attachment(ec2, eni_id):
    """The ENI's attachment block from a paginated DescribeNetworkInterfaces, or None."""
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            NetworkInterfaceIds=[eni_id]):
        for eni in page["NetworkInterfaces"]:
            if eni["NetworkInterfaceId"] == eni_id:
                return eni.get("Attachment")
    raise AssertionError(f"{eni_id} not found in any page of DescribeNetworkInterfaces")


def _detach_and_wait(ec2, eni_id, attachment_id, timeout_s=300):
    """Detach the interface and wait (bounded) for the attachment to be gone: the ENI
    cannot be deleted while attached. An already-detached interface is not an error."""
    try:
        ec2.detach_network_interface(AttachmentId=attachment_id, Force=True)
    except ClientError as exc:
        if _code(exc) not in ("InvalidAttachmentID.NotFound", "IncorrectState"):
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if _attachment(ec2, eni_id) is None:
                return
        except ClientError as exc:
            if _code(exc) == "InvalidNetworkInterfaceID.NotFound":
                return
            raise
        time.sleep(5)


def _nic_report(primary_mac, second_mac):
    """Guest script reporting each MAC's kernel interface and IPv4 addresses, and the IMDS MACs."""
    return [
        "set -uo pipefail",
        _IMDS,
        'addrs() {',
        '  D=""',
        '  for d in /sys/class/net/*; do',
        '    [ "$(cat $d/address 2>/dev/null)" = "$1" ] && D=${d##*/}',
        '  done',
        '  if [ -z "$D" ]; then echo "none none"; return; fi',
        "  echo \"$D $(ip -4 -o addr show dev \"$D\" | awk '{print $4}' | cut -d/ -f1 "
        "| tr '\\n' ',')\"",
        '}',
        f'set -- $(addrs {primary_mac}); PIF=$1; PADDR=${{2:-none}}',
        f'set -- $(addrs {second_mac}); SIF=$1; SADDR=${{2:-none}}',
        "MACS=$(md network/interfaces/macs/ | tr -d '/' | tr '\\n' ',')",
        'echo "SIM2REAL-NICS pif=$PIF paddr=$PADDR sif=$SIF saddr=$SADDR macs=$MACS"',
    ]

def _attached_view(view, second_ip, second_mac):
    """The guest has the new interface up with its address, and its metadata lists the new MAC."""
    view = view or {}
    return (view.get("sif") not in (None, "none") and second_ip in _csv(view.get("saddr"))
            and second_mac in _csv(view.get("macs")))


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Hot-attaching a second ENI to a running instance makes a new guest interface appear with that
    ENI's MAC and private address, and detaching it removes the interface again; the primary
    interface is untouched throughout.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "secip-eni-hot-attach"

    catalog = []
    for page in ec2.get_paginator("describe_instance_types").paginate(InstanceTypes=[ITYPE]):
        catalog += page["InstanceTypes"]
    assert len(catalog) == 1, (
        f"DescribeInstanceTypes({ITYPE!r}) returned {len(catalog)} entries: {catalog!r}"
    )
    max_enis = catalog[0]["NetworkInfo"]["MaximumNetworkInterfaces"]
    assert max_enis > _DEVICE_INDEX, (
        f"{ITYPE} declares MaximumNetworkInterfaces={max_enis}, so device index {_DEVICE_INDEX} "
        f"cannot be occupied and this check would be vacuous"
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
          timeout_s=_bounded(ctx, 600), interval_s=2.0,
          what=f"instance {target} reaching 'running'")
    primary = _primary_eni(ec2, target)
    primary_mac, primary_ip = primary["MacAddress"], primary["PrivateIpAddress"]
    _wait_ssm_online(ctx, ssm, [target])

    second = ec2.create_network_interface(
        SubnetId=subnet, Groups=[sg],
        Description="sim2real-behav secip hot-attach interface",
        TagSpecifications=[{"ResourceType": "network-interface",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["NetworkInterface"]
    second_id, second_mac = second["NetworkInterfaceId"], second["MacAddress"]
    second_ip = second["PrivateIpAddress"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_network_interface(NetworkInterfaceId=second_id)))
    assert ipaddress.ip_address(second_ip) in ipaddress.ip_network(_SUBNET_CIDR), (
        f"the new interface's address {second_ip!r} is outside the subnet CIDR {_SUBNET_CIDR}"
    )
    assert second_mac != primary_mac, (
        f"EC2 handed the new interface the SAME MAC as the primary one ({second_mac!r}); the guest "
        f"could not tell them apart"
    )

    before = _report(_run_guest(ctx, ssm, target, _nic_report(primary_mac, second_mac),
                               "the guest's NIC view BEFORE the attach"), "SIM2REAL-NICS")
    assert before and before.get("pif") != "none", (
        f"the guest could not resolve its own primary MAC {primary_mac!r}; it reported {before!r}"
    )
    assert before["sif"] == "none", (
        f"the guest already has an interface for MAC {second_mac!r} BEFORE the attach "
        f"({before['sif']!r}) — nothing later could be attributed to the attach; it reported "
        f"{before!r}"
    )
    assert second_mac not in _csv(before.get("macs")), (
        f"the instance's own metadata already lists MAC {second_mac!r} before the attach: "
        f"{sorted(_csv(before.get('macs')))!r}"
    )

    attachment_id = ec2.attach_network_interface(
        InstanceId=target, NetworkInterfaceId=second_id,
        DeviceIndex=_DEVICE_INDEX)["AttachmentId"]
    ctx.on_cleanup(lambda: _detach_and_wait(ec2, second_id, attachment_id))
    att = _poll(lambda: _attachment(ec2, second_id),
                lambda a: a is not None and a.get("Status") == "attached",
                timeout_s=_bounded(ctx, 240), interval_s=2.0,
                what=f"{second_id} reaching attachment status 'attached' on {target}")
    assert att["InstanceId"] == target and att["DeviceIndex"] == _DEVICE_INDEX, (
        f"the attachment reports instance {att.get('InstanceId')!r} at device index "
        f"{att.get('DeviceIndex')!r}, expected {target!r} at {_DEVICE_INDEX}"
    )
    assert _instance_state(ec2, target) == "running", (
        f"the instance must stay 'running' across a HOT attach, but it is "
        f"{_instance_state(ec2, target)!r}"
    )

    # The guest network utilities bring the interface up some seconds after 'attached'.
    after = _report(
        _poll(lambda: _run_guest(ctx, ssm, target, _nic_report(primary_mac, second_mac),
                                 "the guest's NIC view AFTER the attach"),
              lambda o: _attached_view(_report(o, "SIM2REAL-NICS"), second_ip, second_mac),
              timeout_s=_bounded(ctx, 300), interval_s=2.0,
              what=f"the guest growing an interface for MAC {second_mac} carrying {second_ip}"),
        "SIM2REAL-NICS")
    assert after["sif"] != before["pif"], (
        f"the guest resolved the new MAC to the SAME interface as the primary one "
        f"({after['sif']!r}) — a second ENI must appear as a SEPARATE device; it reported {after!r}"
    )
    assert second_ip in _csv(after.get("saddr")), (
        f"the new interface {after['sif']!r} inside the guest does not carry the address "
        f"{second_ip!r} that DescribeNetworkInterfaces reports for {second_id} — it carries "
        f"{sorted(_csv(after.get('saddr')))!r}. The attachment was recorded but the device was not "
        f"plugged in"
    )
    assert second_mac in _csv(after.get("macs")) and primary_mac in _csv(after.get("macs")), (
        f"the instance's own metadata must enumerate BOTH attached MACs, but it listed "
        f"{sorted(_csv(after.get('macs')))!r}"
    )
    assert primary_ip in _csv(after.get("paddr")), (
        f"the primary interface must be untouched by the attach, but it now carries "
        f"{sorted(_csv(after.get('paddr')))!r} and not {primary_ip!r}"
    )

    _detach_and_wait(ec2, second_id, attachment_id, timeout_s=_bounded(ctx, 300))
    assert _attachment(ec2, second_id) is None, (
        f"{second_id} still reports an attachment after the detach: "
        f"{_attachment(ec2, second_id)!r}"
    )
    gone = _report(
        _poll(lambda: _run_guest(ctx, ssm, target, _nic_report(primary_mac, second_mac),
                                 "the guest's NIC view AFTER the detach"),
              lambda o: (_report(o, "SIM2REAL-NICS") or {}).get("sif") == "none"
              and second_mac not in _csv((_report(o, "SIM2REAL-NICS") or {}).get("macs")),
              timeout_s=_bounded(ctx, 300), interval_s=2.0,
              what=f"the guest losing the interface for MAC {second_mac}"),
        "SIM2REAL-NICS")
    assert second_mac not in _csv(gone.get("macs")), (
        f"the instance's own metadata still lists the detached MAC {second_mac!r}: "
        f"{sorted(_csv(gone.get('macs')))!r}"
    )
    assert primary_ip in _csv(gone.get("paddr")), (
        f"the primary interface must survive the detach of the second one, but the guest reports "
        f"{sorted(_csv(gone.get('paddr')))!r} on {gone.get('pif')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
