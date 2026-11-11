"""obs-ec2-2-ebs-write-series-follows-the-volume-across-a-move-to-a-second-instance."""
from __future__ import annotations

import datetime
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-ec2-2-ebs-write-series-follows-the-volume-across-a-move-to-a-second-instance"
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
_FIRST_MIB = 24
_SECOND_MIB = 40
_MIB = 1024 * 1024


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
    """`ctx` whose cleanups run AT MOST ONCE and can be unwound in-body, inside the check's budget.
    Post-run cleanup is bounded to 60 s, shorter than terminating an instance and deleting its
    network; each callable is also registered with the real ctx in case the body is killed.
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
    Built rather than borrowed because an account may have no default VPC; egress lets the SSM
    agent register.
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
    """One AWS/EBS series on the dimension set EXACTLY [VolumeId], Period=60, Sum."""
    resp = cw.get_metric_statistics(
        Namespace="AWS/EBS", MetricName=metric,
        Dimensions=[{"Name": "VolumeId", "Value": volume_id}],
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
    )
    return sorted(resp["Datapoints"], key=lambda d: d["Timestamp"])


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _dev(volume_id):
    """The guest path that names a volume BY ITS EBS SERIAL, not by an attach-order guess."""
    return "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_" + volume_id.replace("-", "")


def _attach_and_wait(ec2, dl, volume_id, instance_id):
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    return _poll(dl, lambda: _volume(ec2, volume_id),
                 lambda v: v is not None and v["State"] == "in-use" and v.get("Attachments")
                 and v["Attachments"][0]["State"] == "attached"
                 and v["Attachments"][0]["InstanceId"] == instance_id,
                 cap_s=120, interval_s=2.0, what=f"{volume_id} attaching to {instance_id}")


def _guest_write(ctx, dl, instance_id, volume_id, mib, seek_mib):
    """Write `mib` MiB at offset `seek_mib` to the device whose EBS serial is volume_id."""
    dev = _dev(volume_id)
    lines = [
        "set -uo pipefail",
        f"for i in $(seq 1 60); do [ -e {dev} ] && break; sleep 1; done",
        f'echo "EBS-SERIAL $(lsblk -dno SERIAL $(readlink -f {dev}) | tr -d " ")"',
        "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')",
        'echo "EBS-IID $(curl -s -m 10 -H "X-aws-ec2-metadata-token: $TOK"'
        ' http://169.254.169.254/latest/meta-data/instance-id)"',
        f"dd if=/dev/urandom of={dev} bs=1M count={mib} seek={seek_mib} oflag=direct conv=fsync"
        " 2> /tmp/sim2real-dd.err; echo \"EBS-DD-RC $?\"",
        "echo \"EBS-DD $(grep -o '^[0-9]* bytes' /tmp/sim2real-dd.err | tr -dc 0-9)\"",
    ]
    inv = _run_shell(ctx, dl, instance_id, lines, what=f"writing {mib} MiB to {volume_id}")
    out = inv.get("StandardOutputContent", "")
    assert inv["Status"] == "Success", (
        f"the in-guest write on {instance_id} was {inv['Status']!r}: stdout={out!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert _marker(out, "EBS-IID") == instance_id, (
        f"the guest that ran the write is {_marker(out, 'EBS-IID')!r}, not {instance_id!r}"
    )
    assert _marker(out, "EBS-SERIAL") == volume_id.replace("-", ""), (
        f"the device behind {dev} on {instance_id} is not {volume_id}: stdout={out!r}"
    )
    assert _marker(out, "EBS-DD-RC") == "0", f"dd failed on {instance_id}: stdout={out!r}"
    assert int(_marker(out, "EBS-DD") or 0) == mib * _MIB, (
        f"dd on {instance_id} did not write {mib * _MIB} bytes: stdout={out!r}"
    )




# timing:real-time — metric: 60 s https://docs.aws.amazon.com/ebs/latest/userguide/using_cloudwatch_ebs.html
@tags(
    "axis:happy-path",
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
    """VolumeWriteBytes is keyed by the volume: writes from one guest, then from a second after the
    volume moves to it, land in one [VolumeId] series in separate buckets covering each write,
    and no [VolumeId, InstanceId] series exists for either writer.
    """
    own = _Owned(ctx)
    ctx = own
    try:
        dl = _Deadline(_DEADLINE_S)
        scenario = "obs-ec2-2-ebs-series-follows-volume"
        ec2 = ctx.client("ec2")
        cw = ctx.client("cloudwatch")
        first, second = _FIRST_MIB * _MIB, _SECOND_MIB * _MIB

        az = _usable_az(ec2)
        subnet_id, sg_id = _network(ctx, scenario, az)
        profile_name = _instance_profile(ctx, scenario)
        ids = []
        for _ in range(2):
            inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                           scenario=scenario)
            iid = inst["InstanceId"]
            ctx.on_cleanup(lambda iid=iid: _terminate_and_wait(ec2, iid))
            ids.append(iid)
        one, two = ids
        vol = ec2.create_volume(
            AvailabilityZone=az, Size=1, VolumeType="gp3",
            TagSpecifications=[{"ResourceType": "volume",
                                "Tags": [{"Key": "sim2real", "Value": scenario}]}])["VolumeId"]
        ctx.on_cleanup(lambda: _drop_volume(ec2, vol))
        dl.log(f"instances {ids} volume {vol} in {az}")
        _poll(dl, lambda: (_volume(ec2, vol) or {}).get("State"), lambda s: s == "available",
              cap_s=120, interval_s=2.0, what=f"{vol} reaching 'available'")
        for iid in ids:
            _poll(dl, lambda iid=iid: _instance(ec2, iid),
                  lambda i: i is not None and i["State"]["Name"] == "running",
                  cap_s=300, interval_s=3.0, what=f"instance {iid} reaching 'running'")

        _attach_and_wait(ec2, dl, vol, one)
        for iid in ids:
            _wait_online(ctx, dl, iid)
        start = _minute(_now()) - datetime.timedelta(minutes=2)
        _guest_write(ctx, dl, one, vol, _FIRST_MIB, 0)
        dl.log(f"{one} wrote {first}")

        def _bytes():
            return _series(cw, vol, "VolumeWriteBytes", start, _now() + datetime.timedelta(minutes=1))

        after_one = _poll(dl, _bytes, lambda p: sum(d["Sum"] for d in p) >= first,
                          cap_s=240, interval_s=10.0,
                          what=f"VolumeWriteBytes for {vol} covering the {first} bytes {one} wrote")
        first_bucket = max(p["Timestamp"] for p in after_one)
        dl.log(f"after writer one {[(p['Timestamp'].isoformat(), p['Sum']) for p in after_one]}")

        ec2.detach_volume(VolumeId=vol, InstanceId=one)
        _poll(dl, lambda: _volume(ec2, vol),
              lambda v: v is not None and v["State"] == "available" and not v.get("Attachments"),
              cap_s=120, interval_s=2.0, what=f"{vol} detaching from {one}")
        moved = _attach_and_wait(ec2, dl, vol, two)
        assert moved["Attachments"][0]["InstanceId"] == two, (
            f"{vol} must now be attached to {two}: {moved['Attachments']!r}"
        )
        # Write again only once past writer one's bucket, so the two writers' bytes stay separable.
        _poll(dl, _now, lambda t: _minute(t) > first_bucket, cap_s=90, interval_s=2.0,
              what=f"the clock passing writer one's bucket {first_bucket.isoformat()}")

        _guest_write(ctx, dl, two, vol, _SECOND_MIB, _FIRST_MIB)
        dl.log(f"{two} wrote {second}")
        seen = _poll(dl, _bytes,
                     lambda p: sum(d["Sum"] for d in p if d["Timestamp"] > first_bucket) >= second,
                     cap_s=240, interval_s=10.0,
                     what=(f"VolumeWriteBytes for {vol} gaining a bucket after "
                           f"{first_bucket.isoformat()} that covers the {second} bytes {two} wrote"))
        dl.log(f"after writer two {[(p['Timestamp'].isoformat(), p['Sum']) for p in seen]}")
        early = sum(p["Sum"] for p in seen if p["Timestamp"] <= first_bucket)
        late = sum(p["Sum"] for p in seen if p["Timestamp"] > first_bucket)
        assert first <= early < first + second, (
            f"the bucket(s) through {first_bucket.isoformat()} hold {early!r} bytes; writer one wrote "
            f"{first} and writer two's {second} came later -- {seen!r}"
        )
        assert late >= second, (
            f"the later bucket(s) hold {late!r} bytes, less than the {second} writer two wrote: {seen!r}"
        )

        end = _now() + datetime.timedelta(minutes=1)
        for iid in ids:
            per_instance = cw.get_metric_statistics(
                Namespace="AWS/EBS", MetricName="VolumeWriteBytes",
                Dimensions=[{"Name": "VolumeId", "Value": vol},
                            {"Name": "InstanceId", "Value": iid}],
                StartTime=start, EndTime=end, Period=60, Statistics=["Sum"])["Datapoints"]
            assert per_instance == [], (
                f"a [VolumeId, InstanceId={iid}] series returned {per_instance!r}; the volume's bytes "
                "are published under [VolumeId] alone, whichever instance wrote them"
            )
        assert dl.left() >= 0, f"the check overran its {_DEADLINE_S}s deadline: {dl.elapsed():.0f}s"
        dl.log("done")
    finally:
        own.unwind()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
