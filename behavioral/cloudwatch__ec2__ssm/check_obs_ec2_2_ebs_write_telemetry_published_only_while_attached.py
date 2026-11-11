"""obs-ec2-2-ebs-write-telemetry-published-only-while-attached."""
from __future__ import annotations

import datetime
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-ec2-2-ebs-write-telemetry-published-only-while-attached"
GROUP = 'ebs-telemetry'
SERVICES = ['cloudwatch', 'ec2', 'ssm']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

#: The whole check, setup to last assertion, must finish inside this many seconds. Every wait below
#: is capped by what is left of it, so a target that never publishes fails here rather than hanging.
_DEADLINE_S = 600
_WRITE_MIB = 64
_WRITE_BYTES = _WRITE_MIB * 1024 * 1024


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


class _Deadline:
    """One wall-clock budget for the whole check; every wait draws on what is left of it."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.t0 = time.monotonic()

    def elapsed(self):
        return time.monotonic() - self.t0

    def left(self):
        return self.seconds - self.elapsed()

    def log(self, msg):
        print(f"[{CHECK} +{self.elapsed():6.1f}s] {msg}", file=sys.stderr, flush=True)


class _Owned:
    """`ctx` whose cleanups run at most once and can be unwound in-body.

    The post-check cleanup pass is bounded at 60 s, too short to terminate an instance and delete
    its network, so `run` unwinds the stack itself; each step is also registered with `ctx`.
    """

    def __init__(self, ctx):
        self._ctx = ctx
        self._stack = []

    def __getattr__(self, name):
        return getattr(self._ctx, name)

    def on_cleanup(self, fn):
        state = {"done": False}

        def _once():
            if not state["done"]:
                state["done"] = True
                fn()

        self._stack.append(_once)
        self._ctx.on_cleanup(_once)

    def unwind(self):
        """Run every registered teardown, LIFO; a failure is reported as a LEAK, never raised."""
        while self._stack:
            fn = self._stack.pop()
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 -- must not mask the check's own verdict
                print(f"{CHECK}: teardown step failed: {exc!r}", file=sys.stderr)


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=5.0):
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


def _poll(dl, probe, predicate, *, cap_s, interval_s=5.0, what=""):
    """Poll probe() until predicate(result), bounded by min(cap_s, what is left of the deadline)."""
    budget = max(0.0, min(cap_s, dl.left()))
    end = time.monotonic() + budget
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= end:
            raise AssertionError(
                f"{what or 'condition'} not met within {budget:.0f}s "
                f"(check-wide deadline {dl.seconds}s, {dl.elapsed():.0f}s used; "
                f"last observed: {last!r})"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency",
                                             "VolumeInUse", "IncorrectState"),
                       attempts=60, delay=5.0):
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = _code(exc)
            if code in gone:
                return None
            if code in busy and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH 'available' and offers instance_type (both halves are load-bearing)."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _network(ctx, scenario, az, cidr="10.176.0.0/16", subnet_cidr="10.176.1.0/24"):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Built rather than borrowed: a fresh account may have no default VPC. Egress is what lets the
    SSM agent register. Every resource is tagged in the SAME call that creates it.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]

    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag}],
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _delete_with_retry(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            gone=("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound",
                  "InvalidVpcID.NotFound"))
        _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
                           gone=("InvalidInternetGatewayID.NotFound",))

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0"),
        gone=("InvalidRoute.NotFound", "InvalidRouteTableID.NotFound")))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-ebsmetric-"), VpcId=vpc_id,
        Description="sim2real ebs-telemetry egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id


def _instance_profile(ctx, scenario):
    """A profile whose role can register with SSM, and nothing else."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ebsmetric-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real ebs-telemetry managed instance role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_role():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
        except ClientError as exc:
            if _code(exc) != "NoSuchEntity":
                raise
        _delete_with_retry(lambda: iam.delete_role(RoleName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)

    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_profile():
        _delete_with_retry(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=name, RoleName=name), gone=("NoSuchEntity",),
            busy=("DeleteConflict",))
        _delete_with_retry(lambda: iam.delete_instance_profile(InstanceProfileName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _instance(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', which is when the ENI and root volume go away."""
    # SkipOsShutdown: the guest holds nothing worth a graceful shutdown, and the slow part of this
    # teardown is waiting for 'terminated' before the network can go.
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id],
                                                         SkipOsShutdown=True))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        inst = _instance(ec2, instance_id)
        if inst is None or inst["State"]["Name"] == "terminated":
            return
        time.sleep(5)
    raise RuntimeError(f"{instance_id} not terminated within {timeout_s}s")


def _volume(ec2, volume_id):
    try:
        return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    except ClientError as exc:
        if _code(exc) == "InvalidVolume.NotFound":
            return None
        raise


def _drop_volume(ec2, volume_id):
    """Force-detach if still attached (a failed run can leave it so), then delete."""
    vol = _volume(ec2, volume_id)
    if vol is None:
        return
    if vol.get("Attachments"):
        try:
            ec2.detach_volume(VolumeId=volume_id, Force=True)
        except ClientError as exc:
            if _code(exc) not in ("IncorrectState", "InvalidAttachment.NotFound"):
                raise
    _delete_with_retry(lambda: ec2.delete_volume(VolumeId=volume_id),
                       gone=("InvalidVolume.NotFound",))


def _launch(ctx, *, profile_name, subnet_id, sg_id, scenario):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=40, delay=3.0)
    return resv["Instances"][0]


def _wait_online(ctx, dl, instance_id):
    """Wait for the SSM agent on this host to report Online. Never registering is a FAIL."""
    ssm = ctx.client("ssm")

    def _view():
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        rows = [i for i in resp["InstanceInformationList"] if i.get("InstanceId") == instance_id]
        return rows[0] if rows else None

    return _poll(dl, _view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 cap_s=420, interval_s=5.0,
                 what=f"the SSM agent on {instance_id} coming Online")


def _run_shell(ctx, dl, instance_id, commands, *, what):
    """Send commands to the guest and return its terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=120,
        Comment="sim2real ebs-telemetry in-guest"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll(dl, _inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 cap_s=180, interval_s=2.0,
                 what=f"{what}: invocation {command_id} reaching a terminal status")


def _marker(stdout, marker):
    """The text after `marker` on the LAST line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


def _minute(ts):
    return ts.replace(second=0, microsecond=0)


def _series(cw, volume_id, metric, start, end):
    """One AWS/EBS series on the dimension set exactly [VolumeId], Period=60, Sum."""
    resp = cw.get_metric_statistics(
        Namespace="AWS/EBS", MetricName=metric,
        Dimensions=[{"Name": "VolumeId", "Value": volume_id}],
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
    )
    return sorted(resp["Datapoints"], key=lambda d: d["Timestamp"])


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/ebs/latest/userguide/using_cloudwatch_ebs.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """AWS/EBS write metrics are published for an attached volume's guest-written bytes; a never-attached
    twin publishes nothing, and after detach no new bucket appears while the root volume publishes.
    """
    own = _Owned(ctx)
    ctx = own
    try:
        dl = _Deadline(_DEADLINE_S)
        scenario = "obs-ec2-2-ebs-write-telemetry"
        ec2 = ctx.client("ec2")
        cw = ctx.client("cloudwatch")

        az = _usable_az(ec2)
        subnet_id, sg_id = _network(ctx, scenario, az)
        profile_name = _instance_profile(ctx, scenario)

        inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                       scenario=scenario)
        instance_id = inst["InstanceId"]
        ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
        dl.log(f"launched {instance_id} in {az}")
        assert inst["Placement"]["AvailabilityZone"] == az, (
            f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
        )

        # Two identical volumes, created together: only one is attached, so the twin shows the
        # metric is attachment-driven rather than time-driven.
        vol_tags = [{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": scenario}]}]
        target = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3",
                                   TagSpecifications=vol_tags)["VolumeId"]
        ctx.on_cleanup(lambda: _drop_volume(ec2, target))
        control = ec2.create_volume(AvailabilityZone=az, Size=1, VolumeType="gp3",
                                    TagSpecifications=vol_tags)["VolumeId"]
        ctx.on_cleanup(lambda: _drop_volume(ec2, control))
        created_at = _now()
        dl.log(f"volumes target={target} control={control}")

        _poll(dl, lambda: [(_volume(ec2, v) or {}).get("State") for v in (target, control)],
              lambda s: s == ["available", "available"], cap_s=120, interval_s=2.0,
              what="both new volumes reaching 'available'")
        running = _poll(dl, lambda: _instance(ec2, instance_id),
                        lambda i: i is not None and i["State"]["Name"] == "running",
                        cap_s=300, interval_s=3.0, what=f"instance {instance_id} reaching 'running'")
        root_dev = running["RootDeviceName"]
        root = [m["Ebs"]["VolumeId"] for m in running["BlockDeviceMappings"]
                if m["DeviceName"] == root_dev]
        assert len(root) == 1, (
            f"the instance must report exactly one EBS volume at its root device {root_dev!r}: "
            f"{running['BlockDeviceMappings']!r}"
        )
        root_vol = root[0]
        dl.log(f"running; root volume {root_vol}")

        # --- attach the target, and only the target ---------------------------
        attach_minute = _minute(_now())
        ec2.attach_volume(VolumeId=target, InstanceId=instance_id, Device="/dev/sdf")
        attached = _poll(dl, lambda: _volume(ec2, target),
                         lambda v: v is not None and v["State"] == "in-use"
                         and v.get("Attachments") and v["Attachments"][0]["State"] == "attached",
                         cap_s=120, interval_s=2.0, what=f"{target} attaching to {instance_id}")
        assert attached["Attachments"][0]["InstanceId"] == instance_id, (
            f"{target} reports attachment {attached['Attachments']!r}, not to {instance_id!r}"
        )
        assert (_volume(ec2, control) or {}).get("State") == "available", (
            f"the control volume {control} must remain unattached, got {_volume(ec2, control)!r}"
        )
        dl.log("target attached")

        _wait_online(ctx, dl, instance_id)
        dl.log("ssm online")

        # --- the act: real bytes onto the attached device, from inside the guest ----
        # The device is addressed by its EBS serial and written with O_DIRECT + fsync.
        serial = target.replace("-", "")
        dev = f"/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_{serial}"
        lines = [
            "set -uo pipefail",
            f"for i in $(seq 1 60); do [ -e {dev} ] && break; sleep 1; done",
            f'echo "EBS-DEV $(readlink -f {dev})"',
            f'echo "EBS-SERIAL $(lsblk -dno SERIAL $(readlink -f {dev}) | tr -d " ")"',
            'echo "EBS-T0 $(date +%s)"',
            f"dd if=/dev/urandom of=/tmp/sim2real-ebs-payload bs=1M count={_WRITE_MIB} status=none",
            f"dd if=/tmp/sim2real-ebs-payload of={dev} bs=1M count={_WRITE_MIB} oflag=direct"
            " conv=fsync 2> /tmp/sim2real-dd.err; echo \"EBS-DD-RC $?\"",
            "echo \"EBS-DD $(grep -o '^[0-9]* bytes' /tmp/sim2real-dd.err | tr -dc 0-9)\"",
            'echo "EBS-T1 $(date +%s)"',
            f'echo "EBS-READBACK $(head -c {_WRITE_BYTES} {dev} | sha256sum | cut -c1-64)"',
            'echo "EBS-PAYLOAD $(sha256sum /tmp/sim2real-ebs-payload | cut -c1-64)"',
            "rm -f /tmp/sim2real-ebs-payload",
        ]
        write_at = _now()
        inv = _run_shell(ctx, dl, instance_id, lines, what=f"writing {_WRITE_MIB} MiB to {target}")
        out = inv.get("StandardOutputContent", "")
        assert inv["Status"] == "Success", (
            f"the in-guest write was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
            f"stdout={out!r} stderr={inv.get('StandardErrorContent')!r}"
        )
        assert _marker(out, "EBS-SERIAL") == serial, (
            f"the guest device behind {dev} reports serial {_marker(out, 'EBS-SERIAL')!r}, not "
            f"{serial!r} -- the bytes would land on some other volume; stdout={out!r}"
        )
        assert _marker(out, "EBS-DD-RC") == "0", f"dd to {dev} failed in the guest: stdout={out!r}"
        written = int(_marker(out, "EBS-DD") or 0)
        assert written == _WRITE_BYTES, (
            f"dd inside the guest reported {written!r} bytes written to {dev}, expected {_WRITE_BYTES}"
        )
        assert _marker(out, "EBS-READBACK") == _marker(out, "EBS-PAYLOAD"), (
            f"the device does not hold the payload just written: readback "
            f"{_marker(out, 'EBS-READBACK')!r} vs payload {_marker(out, 'EBS-PAYLOAD')!r}"
        )
        dl.log(f"guest wrote {written} bytes to {_marker(out, 'EBS-DEV')}")

        # --- the effect on the attached volume, and the barrier for the twin ---------
        window_start = _minute(created_at) - datetime.timedelta(minutes=2)
        write_minute = _minute(write_at)

        def _target_view():
            end = _now() + datetime.timedelta(minutes=1)
            return (_series(cw, target, "VolumeWriteBytes", window_start, end),
                    _series(cw, target, "VolumeWriteOps", window_start, end))

        wbytes, wops = _poll(
            dl, _target_view,
            lambda v: any(p["Timestamp"] >= write_minute for p in v[0])
            and sum(p["Sum"] for p in v[0]) >= _WRITE_BYTES
            and sum(p["Sum"] for p in v[1]) > 0,
            cap_s=480, interval_s=10.0,
            what=(f"AWS/EBS VolumeWriteBytes Sum >= {_WRITE_BYTES} and VolumeWriteOps > 0 for "
                  f"{target} on [VolumeId], Period=60"))
        dl.log(f"target bytes buckets={[(p['Timestamp'].isoformat(), p['Sum']) for p in wbytes]} "
               f"ops={[(p['Timestamp'].isoformat(), p['Sum']) for p in wops]}")
        total_bytes = sum(p["Sum"] for p in wbytes)
        assert total_bytes >= _WRITE_BYTES, (
            f"VolumeWriteBytes Sum for {target} is {total_bytes!r}, below the {_WRITE_BYTES} bytes the "
            f"guest wrote: {wbytes!r}"
        )
        assert sum(p["Sum"] for p in wops) > 0, f"VolumeWriteOps for {target} is zero: {wops!r}"
        early = [p for p in wbytes + wops if p["Timestamp"] < attach_minute]
        assert early == [], (
            f"{target} has bucket(s) {early!r} from before it was attached at "
            f"{attach_minute.isoformat()} -- an unattached volume must not publish"
        )
        latest_target = max(p["Timestamp"] for p in wbytes)

        barrier_end = _now() + datetime.timedelta(minutes=1)
        for metric in ("VolumeWriteBytes", "VolumeWriteOps"):
            twin = _series(cw, control, metric, window_start, barrier_end)
            assert twin == [], (
                f"the never-attached twin {control} published {metric} {twin!r} while the attached "
                f"{target} had already published through {latest_target.isoformat()} -- the metric "
                "must be attachment-driven, not time-driven"
            )
        dl.log("twin silent at the barrier")

        # --- detach, then no new bucket while the root volume keeps publishing ------
        ec2.detach_volume(VolumeId=target, InstanceId=instance_id)
        _poll(dl, lambda: _volume(ec2, target),
              lambda v: v is not None and v["State"] == "available" and not v.get("Attachments"),
              cap_s=120, interval_s=2.0, what=f"{target} detaching to 'available'")
        detached_at = _now()
        first_new = _minute(detached_at) + datetime.timedelta(minutes=1)
        dl.log(f"detached; any target bucket >= {first_new.isoformat()} is new")

        def _root_later():
            pts = _series(cw, root_vol, "VolumeWriteOps", first_new,
                          _now() + datetime.timedelta(minutes=1))
            return [p for p in pts if p["Timestamp"] >= first_new]

        root_after = _poll(dl, _root_later, lambda p: len(p) >= 2, cap_s=300, interval_s=10.0,
                           what=(f"the still-attached root volume {root_vol} publishing two "
                                 f"VolumeWriteOps buckets at/after {first_new.isoformat()}"))
        dl.log(f"root later buckets {[(p['Timestamp'].isoformat(), p['Sum']) for p in root_after]}")

        probe_end = _now() + datetime.timedelta(minutes=1)
        for metric in ("VolumeWriteBytes", "VolumeWriteOps"):
            late = [p for p in _series(cw, target, metric, window_start, probe_end)
                    if p["Timestamp"] >= first_new]
            assert late == [], (
                f"{target} published {metric} bucket(s) {late!r} after it detached at "
                f"{detached_at.isoformat()}, while the root volume {root_vol} on the same instance "
                f"published {len(root_after)} later bucket(s) -- a detached volume must stop publishing"
            )
        still_twin = _series(cw, control, "VolumeWriteBytes", window_start, probe_end)
        assert still_twin == [], (
            f"the never-attached twin {control} published VolumeWriteBytes {still_twin!r}"
        )
        assert dl.left() >= 0, f"the check overran its {_DEADLINE_S}s deadline: {dl.elapsed():.0f}s"
        dl.log("done")
    finally:
        own.unwind()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
