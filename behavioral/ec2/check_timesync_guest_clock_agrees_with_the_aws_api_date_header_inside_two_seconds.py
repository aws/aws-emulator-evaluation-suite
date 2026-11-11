"""timesync-guest-clock-agrees-with-the-aws-api-date-header-inside-two-seconds."""
from __future__ import annotations

import json
import random
import re
import time
from email.utils import parsedate_to_datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "timesync-guest-clock-agrees-with-the-aws-api-date-header-inside-two-seconds"
GROUP = 'timesync-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
SSM_CORE_POLICY = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
#: The Amazon Time Sync link-local address, and the same 32 bits in the form chrony prints them.
#: The refid is asserted because it is the peer chrony is exchanging NTP packets with; without it
#: the clock agreement below could have come from any time source, or from luck.
TIMESYNC_IP = '169.254.169.123'
TIMESYNC_REFID = 'A9FEA97B'
#: The HTTP Date header carries whole seconds, so one second of the bound is truncation alone and
#: the rest is round-trip time. On AWS the guest's own epoch and the header it fetched in the
#: next breath land in the same second, i.e. a delta of 0. Two seconds is therefore a tight bound --
#: an unsynchronised guest's clock is off by whatever the hypervisor seeded it with plus drift.
CLOCK_TOLERANCE_S = 2
#: The guest brackets its own fetch with two clock reads. If that window were wide the bracket
#: would be vacuous, so its width is asserted too.
MAX_FETCH_WINDOW_S = 30
THROTTLE = ('RequestLimitExceeded', 'Throttling', 'ThrottlingException', 'TooManyUpdates')
TERMINAL = ('Success', 'Failed', 'TimedOut', 'Cancelled')

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not met within {timeout_s}s. Last observation: {last!r}"
            )
        time.sleep(interval_s)


def _call_with_retry(fn, codes=THROTTLE, retries=30, delay=5.0):
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


def _ssm_ami(ctx, parameter=AL2023_SSM):
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_azs(ctx, instance_type=INSTANCE_TYPE):
    """AZs that are BOTH available and offer the instance type, intersected rather than guessed.

    describe_instance_type_offerings reports no zone state and describe_availability_zones reports
    no instance types, so either alone picks a zone that cannot run the check. An empty
    intersection means this region cannot run it at all, which is a finding and not an AZ to guess.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    return usable


def _network(ctx, scenario, az, ingress=None):
    """A VPC, subnet, route to the internet and security group of this check's own.

    Nothing ambient: a fresh account may have no default VPC or default security group. The CIDR's
    second octet is random in 10/8 because overlapping VPC CIDRs are legal (these VPCs are never
    peered), so a sibling run in the same account cannot collide.
    Egress exists because the SSM agent must reach the SSM endpoint to register at all.
    """
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-ts-")}]
    second = random.randint(64, 191)
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{second}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": kv}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    _poll_until(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
                lambda s: s == "available", timeout_s=120, interval_s=3,
                description=f"vpc {vpc_id} reaches 'available'")

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": kv}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_igw(ctx, igw_id, vpc_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rtb = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=f"10.{second}.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": kv}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet(ctx, subnet_id))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-ts-"), VpcId=vpc_id,
        Description="sim2real timesync check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": kv}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ctx, sg_id))
    if ingress:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ingress)
    return vpc_id, subnet_id, sg_id


def _delete_sg(ctx, sg_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_security_group", GroupId=sg_id)
    except ClientError as exc:
        if _code(exc) != "InvalidGroup.NotFound":
            raise


def _delete_subnet(ctx, subnet_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if _code(exc) != "InvalidSubnetID.NotFound":
            raise


def _delete_igw(ctx, igw_id, vpc_id):
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if _code(exc) not in ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"):
            raise
    try:
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
    except ClientError as exc:
        if _code(exc) != "InvalidInternetGatewayID.NotFound":
            raise


def _delete_vpc(ctx, vpc_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if _code(exc) != "InvalidVpcID.NotFound":
            raise


def _managed_instance_profile(ctx, scenario):
    """An instance profile whose role may register with Systems Manager, and nothing else.

    AmazonSSMManagedInstanceCore is the only policy attached: every assertion in this check is read
    out of a Run Command invocation, so the guest needs no other entitlement, and a narrower role
    means a guest that cannot reach anything the check did not intend it to.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ts-")
    kv = [{"Key": "sim2real", "Value": scenario}]
    iam.create_role(
        RoleName=name,
        Description="sim2real timesync managed-instance role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "ec2.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=kv,
    )
    ctx.on_cleanup(lambda: _drop_role(ctx, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=name, Tags=kv)
    ctx.on_cleanup(lambda: _drop_instance_profile(ctx, name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    # A fresh instance profile is not resolvable by RunInstances at once; _run_instance retries
    # its InvalidParameterValue to a bound, so no fixed wait is needed here.
    return name


def _drop_instance_profile(ctx, name):
    iam = ctx.client("iam")
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(ctx, name):
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=name, PolicyArn=SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) not in ("NoSuchEntity",):
            raise
    for attempt in range(12):
        try:
            iam.delete_role(RoleName=name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _run_instance(ctx, *, ami, subnet_id, sg_id, profile_name, scenario,
                  instance_type=INSTANCE_TYPE):
    """Launch ONE instance, tagged in the same call that creates it.

    Tagging in the creating call leaves no window in which an aborted run holds an untagged
    instance. A brand-new instance profile is not immediately resolvable by RunInstances, hence
    the bounded retry.
    """
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-ts-")}]
    return _call_with_retry(
        lambda: ctx.client("ec2").run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[{"ResourceType": rt, "Tags": kv}
                               for rt in ("instance", "volume")],
        ),
        codes=THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )["Instances"][0]


def _instance_view(ctx, instance_id):
    """DescribeInstances for one id, PAGINATED and filtered, tolerating the launch race.

    A RunInstances that has returned an id is not yet visible to DescribeInstances, which raises
    InvalidInstanceID.NotFound for a few seconds; None means 'not yet or no longer there'.
    """
    ec2 = ctx.client("ec2")
    try:
        for page in ec2.get_paginator("describe_instances").paginate(
                Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
            for resv in page["Reservations"]:
                for inst in resv["Instances"]:
                    if inst["InstanceId"] == instance_id:
                        return inst
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    return None


def _terminate_and_wait(ctx, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', not merely 'shutting-down'.

    The subnet and VPC this check created cannot be deleted while the instance's network interface
    still exists, and the interface outlives 'shutting-down'.
    """
    ec2 = ctx.client("ec2")
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _instance_view(ctx, instance_id)
        if inst is None or inst["State"]["Name"] == "terminated":
            return
        time.sleep(5)


def _agent_online(ctx, instance_id, timeout_s=420):
    """Wait for the SSM agent on this instance to register and ping Online.

    A host that never registers fails the check: the whole point of the check is a reading
    taken inside the guest, and there is no weaker reading that would substitute for it.
    """
    ssm = ctx.client("ssm")

    def view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    return _poll_until(view, lambda i: i is not None and i.get("PingStatus") == "Online",
                       timeout_s=timeout_s, interval_s=5.0,
                       description=f"the SSM agent on {instance_id} coming Online")


def _run_command(ctx, instance_id, commands, *, comment, timeout_s=300):
    """Send one AWS-RunShellScript document and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    command_id = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=600, Comment=comment,
    ))["Command"]["CommandId"]

    def invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll_until(invocation, lambda i: i is not None and i.get("Status") in TERMINAL,
                       timeout_s=timeout_s, interval_s=5.0,
                       description=f"invocation of {command_id} on {instance_id} terminating")


def _sections(stdout):
    """Split guest stdout on its own ===NAME=== markers.

    The guest emits named sections rather than bare lines so that a missing section is
    distinguishable from an empty one, and so no assertion has to index into stdout by position.
    """
    out, cur = {}, None
    for ln in stdout.splitlines():
        marker = re.fullmatch(r"===([A-Z0-9_]+)===", ln.strip())
        if marker:
            cur = marker.group(1)
            out[cur] = []
            continue
        if cur is not None:
            out[cur].append(ln)
    return {k: "\n".join(v).strip() for k, v in out.items()}


def _api_date_epoch(response):
    """The whole-second epoch of an AWS API response's own HTTP Date header.

    This is the control plane's clock as the service itself stamped it, taken from the response
    botocore already parsed rather than from anything this host believes about the time.
    """
    headers = response["ResponseMetadata"]["HTTPHeaders"]
    raw = headers.get("date")
    assert raw, f"the API response carried no Date header: {sorted(headers)!r}"
    return int(parsedate_to_datetime(raw).timestamp()), raw


def _guest_script(endpoint_url):
    """Commands that make the GUEST compare its own clock with the EC2 endpoint's Date header.

    The comparison happens inside the instance, in one breath, so neither Run Command's scheduling
    latency nor this host's clock enters the measurement. The two `date` reads bracket the fetch,
    which is what makes the delta attributable to the guest's clock rather than to the network.
    """
    return [
        "set -uo pipefail",
        "echo '===IID==='",
        "T=$(curl -sS -m 10 -X PUT http://169.254.169.254/latest/api/token "
        "-H 'X-aws-ec2-metadata-token-ttl-seconds: 120')",
        'curl -sS -m 10 -H "X-aws-ec2-metadata-token: $T" '
        "http://169.254.169.254/latest/meta-data/instance-id; echo",
        "echo '===WAITSYNC==='",
        'chronyc waitsync 60 0.1 0.0 10; echo "waitsync_rc=$?"',
        "echo '===REFID==='",
        "for i in $(seq 1 60); do "
        "R=$(chronyc -n tracking | awk -F': *' '/^Reference ID/{print $2}'); "
        f'case "$R" in {TIMESYNC_REFID}*) break;; esac; sleep 2; done',
        "chronyc -n tracking | awk -F': *' '/^Reference ID/{print $2}'",
        "echo '===CLOCK==='",
        'G1=$(date -u +%s)',
        "H=$(curl -sS -m 20 -D - -o /dev/null "
        f"{endpoint_url}/ | tr -d '\\r' | grep -i '^date:' | cut -d' ' -f2-)",
        'G2=$(date -u +%s)',
        'HE=$(date -u -d "$H" +%s)',
        'echo "g1=$G1"',
        'echo "he=$HE"',
        'echo "g2=$G2"',
        'echo "header=$H"',
        "echo '===DONE==='",
    ]


def _kv(text):
    """`k=v` lines as a dict, so no assertion has to index stdout by position."""
    out = {}
    for ln in text.splitlines():
        key, sep, value = ln.strip().partition("=")
        if sep:
            out[key] = value
    return out


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A guest synchronised to the link-local Amazon Time Sync service (chrony refid A9FEA97B) reads
    a wall clock within two seconds of the EC2 endpoint's HTTP Date header, bracketed by the guest's
    own clock reads and by control-plane Date headers taken before and after the command."""
    scenario = "timesync-clock-vs-api-date"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    _vpc_id, subnet_id, sg_id = _network(ctx, scenario, az)
    profile_name = _managed_instance_profile(ctx, scenario)

    instance = _run_instance(ctx, ami=ami, subnet_id=subnet_id, sg_id=sg_id,
                             profile_name=profile_name, scenario=scenario)
    instance_id = instance["InstanceId"]
    # Registered IMMEDIATELY after RunInstances, before any wait: an instance that never boots or
    # never registers must be terminated rather than left billing.
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    assert instance["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {instance['Placement']!r}, not the derived zone {az!r}"
    )
    assert instance["InstanceType"] == INSTANCE_TYPE, (
        f"the instance is a {instance['InstanceType']!r}, expected {INSTANCE_TYPE!r}"
    )

    running = _poll_until(lambda: _instance_view(ctx, instance_id),
                          lambda i: i is not None and i["State"]["Name"] == "running",
                          timeout_s=600, interval_s=5,
                          description=f"instance {instance_id} reaches 'running'")
    assert running["PublicIpAddress"], (
        f"the instance has no public address, so its SSM agent cannot register: {running!r}"
    )
    _agent_online(ctx, instance_id)

    # --- the runner's own bracket, taken from the control plane's Date headers ------------------
    before_epoch, before_raw = _api_date_epoch(ctx.client("ec2").describe_regions())

    inv = _run_command(ctx, instance_id, _guest_script(ctx.service_url(f"https://ec2.{ctx.region}.amazonaws.com")),
                       comment="sim2real timesync clock vs api date")

    after_epoch, after_raw = _api_date_epoch(ctx.client("ec2").describe_regions())
    assert after_epoch >= before_epoch, (
        f"the control plane's own Date header went backwards across the invocation: {before_raw!r} "
        f"then {after_raw!r}"
    )

    assert inv["Status"] == "Success", (
        f"the guest command was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, f"the guest script exited {inv['ResponseCode']!r}"
    assert inv["StandardErrorContent"] == "", (
        f"the guest script wrote to stderr: {inv['StandardErrorContent']!r}"
    )
    stdout = inv["StandardOutputContent"]
    sec = _sections(stdout)
    assert "DONE" in sec, (
        f"the guest script did not run to completion -- sections seen were {sorted(sec)!r}; "
        f"stdout was {stdout!r}"
    )

    # --- the reading is this instance's, and it is synchronised to Amazon Time Sync ------------
    assert sec.get("IID") == instance_id, (
        f"the guest read instance id {sec.get('IID')!r} out of IMDS, but this check launched "
        f"{instance_id!r} -- the reading is not attributable to the instance under test"
    )
    assert "waitsync_rc=0" in sec.get("WAITSYNC", ""), (
        f"`chronyc waitsync` did not report success, so the guest never synchronised to any time "
        f"source and its clock agreeing with anything would be luck: {sec.get('WAITSYNC')!r}"
    )
    assert sec.get("REFID", "").startswith(f"{TIMESYNC_REFID} ({TIMESYNC_IP})"), (
        f"chrony's reference id is {sec.get('REFID')!r}, expected "
        f"{TIMESYNC_REFID + ' (' + TIMESYNC_IP + ')'!r} -- the clock under test is not being "
        f"driven by the link-local Amazon Time Sync service"
    )

    # --- the guest's clock against the endpoint's own Date header ------------------------------
    clock = _kv(sec.get("CLOCK", ""))
    for key in ("g1", "he", "g2"):
        assert key in clock, (
            f"the guest did not report {key!r}; it reported {clock!r} from section "
            f"{sec.get('CLOCK')!r}"
        )
    g1, he, g2 = int(clock["g1"]), int(clock["he"]), int(clock["g2"])
    assert clock.get("header"), (
        f"the guest reported no Date header text, so its parsed epoch cannot be attributed to an "
        f"AWS response: {clock!r}"
    )
    assert g2 - g1 <= MAX_FETCH_WINDOW_S, (
        f"the guest's bracket around its own fetch spans {g2 - g1}s (>{MAX_FETCH_WINDOW_S}s), "
        f"which is too wide for the bracket below to mean anything: {clock!r}"
    )
    assert abs(he - g1) <= CLOCK_TOLERANCE_S, (
        f"the guest's clock read {g1} immediately before fetching a Date header of {he} "
        f"({clock['header']!r}) -- a gap of {he - g1}s, beyond the {CLOCK_TOLERANCE_S}s bound. "
        f"The guest is synchronised to {TIMESYNC_IP} yet disagrees with the API's own clock"
    )
    assert g1 - CLOCK_TOLERANCE_S <= he <= g2 + CLOCK_TOLERANCE_S, (
        f"the Date header's second {he} falls outside the guest's own bracket "
        f"[{g1}, {g2}] widened by {CLOCK_TOLERANCE_S}s: {clock!r}"
    )

    # --- and against the runner's independent bracket over the whole exchange ------------------
    assert before_epoch - CLOCK_TOLERANCE_S <= g1 <= after_epoch + CLOCK_TOLERANCE_S, (
        f"the guest reported epoch {g1}, outside the control plane's own bracket "
        f"[{before_epoch} ({before_raw!r}), {after_epoch} ({after_raw!r})] widened by "
        f"{CLOCK_TOLERANCE_S}s -- the guest's clock is not the same clock AWS is keeping"
    )
    assert before_epoch <= he <= after_epoch, (
        f"the Date header the GUEST fetched ({he}, {clock['header']!r}) falls outside the two the "
        f"runner fetched around it [{before_epoch}, {after_epoch}] -- the two halves of this check "
        f"did not observe the same AWS clock"
    )


# EC2 network teardown: an instance's ENIs outlive its delete, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc fail with DependencyViolation until they go. Wait for them and retry that code inside one
# window shared by all network deletes of the check, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
