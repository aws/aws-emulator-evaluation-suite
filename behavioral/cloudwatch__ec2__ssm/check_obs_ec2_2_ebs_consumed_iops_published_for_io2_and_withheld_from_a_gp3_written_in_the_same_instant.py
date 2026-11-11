"""obs-ec2-2-ebs-consumed-iops-published-for-io2-and-withheld-from-a-gp3-written-in-the-same-instant."""
from __future__ import annotations

import datetime
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-ec2-2-ebs-consumed-iops-published-for-io2-and-withheld-from-a-gp3-written-in-the-same-instant"
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
_WRITE_MIB = 16
_MIB = 1024 * 1024
_IO2_ONLY = ("VolumeConsumedReadWriteOps", "VolumeThroughputPercentage")

# ===== self-contained helpers =====
# _code / _call_with_retry / _delete_with_retry / _usable_az / _network / _instance_profile /
# _instance_state / _terminate_and_wait / _launch / _wait_online / _run_shell / _marker.
# Every wait is bounded by the check-wide _Deadline.


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
    """`ctx`, except every cleanup it registers runs AT MOST ONCE, and can be unwound in-body.

    Terminating an instance and then deleting the network it held takes longer than the standard
    cleanup budget, so `run` unwinds the whole stack itself in a `finally`; each callable is still
    registered with the real `ctx.on_cleanup` the moment its resource exists.
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
    """One AWS/EBS series on the dimension set EXACTLY [VolumeId], Period=60, Sum.

    Scoped to a volume id only this check created, so an empty result is a property of the query
    and never of whatever else this account is running.
    """
    resp = cw.get_metric_statistics(
        Namespace="AWS/EBS", MetricName=metric,
        Dimensions=[{"Name": "VolumeId", "Value": volume_id}],
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
    )
    return sorted(resp["Datapoints"], key=lambda d: d["Timestamp"])


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _bring_up(ctx, dl, scenario, specs):
    """Network, profile, one instance, and one volume per spec, each attached and SSM-reachable.

    Every create is followed at once by the cleanup that undoes it. Volumes are created in the
    instance's AZ and tagged in the create call; each spec is (create_volume kwargs, device).
    Returns (instance_id, [volume ids in spec order]).
    """
    ec2 = ctx.client("ec2")
    az = _usable_az(ec2)
    subnet_id, sg_id = _network(ctx, scenario, az)
    profile_name = _instance_profile(ctx, scenario)
    inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario)
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    dl.log(f"launched {instance_id} in {az}")

    vol_tags = [{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": scenario}]}]
    vols = []
    for kwargs, _device in specs:
        vid = ec2.create_volume(AvailabilityZone=az, TagSpecifications=vol_tags,
                                **kwargs)["VolumeId"]
        ctx.on_cleanup(lambda vid=vid: _drop_volume(ec2, vid))
        vols.append(vid)
    _poll(dl, lambda: [(_volume(ec2, v) or {}).get("State") for v in vols],
          lambda s: s == ["available"] * len(vols), cap_s=120, interval_s=2.0,
          what=f"volumes {vols!r} reaching 'available'")
    _poll(dl, lambda: _instance(ec2, instance_id),
          lambda i: i is not None and i["State"]["Name"] == "running",
          cap_s=300, interval_s=3.0, what=f"instance {instance_id} reaching 'running'")
    for vid, (_kwargs, device) in zip(vols, specs):
        ec2.attach_volume(VolumeId=vid, InstanceId=instance_id, Device=device)
    for vid in vols:
        _poll(dl, lambda vid=vid: _volume(ec2, vid),
              lambda v: v is not None and v["State"] == "in-use" and v.get("Attachments")
              and v["Attachments"][0]["State"] == "attached"
              and v["Attachments"][0]["InstanceId"] == instance_id,
              cap_s=120, interval_s=2.0, what=f"{vid} attaching to {instance_id}")
    _wait_online(ctx, dl, instance_id)
    dl.log(f"volumes {vols} attached; ssm online")
    return instance_id, vols


def _dev(volume_id):
    """The guest path that names a volume BY ITS EBS SERIAL, not by an attach-order guess."""
    return "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_" + volume_id.replace("-", "")


def _wait_dev_lines(volume_id):
    dev = _dev(volume_id)
    return [f"for i in $(seq 1 60); do [ -e {dev} ] && break; sleep 1; done",
            f'echo "EBS-SERIAL-{volume_id} $(lsblk -dno SERIAL $(readlink -f {dev}) | tr -d " ")"']


# ===== end self-contained helpers =====


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
    """`VolumeConsumedReadWriteOps` and `VolumeThroughputPercentage` publish for an io2 volume and
    stay withheld, over two published rounds, from a gp3 volume given the identical write on the
    same instance -- while the gp3 volume's own VolumeWriteBytes proves its pipeline delivered."""
    own = _Owned(ctx)
    ctx = own
    try:
        dl = _Deadline(_DEADLINE_S)
        scenario = "obs-ec2-2-ebs-io2-only-metrics"
        cw = ctx.client("cloudwatch")
        w_bytes = _WRITE_MIB * _MIB

        instance_id, (gp3, io2) = _bring_up(ctx, dl, scenario, [
            ({"Size": 1, "VolumeType": "gp3"}, "/dev/sdf"),
            ({"Size": 4, "VolumeType": "io2", "Iops": 100}, "/dev/sdg"),
        ])
        lines = ["set -uo pipefail"] + _wait_dev_lines(gp3) + _wait_dev_lines(io2)
        for vid in (gp3, io2):
            lines += [
                f"dd if=/dev/urandom of={_dev(vid)} bs=1M count={_WRITE_MIB} oflag=direct conv=fsync"
                f" 2> /tmp/sim2real-{vid}.err; echo \"EBS-RC-{vid} $?\"",
                f"echo \"EBS-W-{vid} $(grep -o '^[0-9]* bytes' /tmp/sim2real-{vid}.err | tr -dc 0-9)\"",
            ]
        start = _minute(_now()) - datetime.timedelta(minutes=5)

        def _write_round(n):
            inv = _run_shell(ctx, dl, instance_id, lines, what=f"write round {n} to {gp3} and {io2}")
            out = inv.get("StandardOutputContent", "")
            assert inv["Status"] == "Success", (
                f"round {n} in-guest write was {inv['Status']!r}: stdout={out!r} "
                f"stderr={inv.get('StandardErrorContent')!r}"
            )
            for vid in (gp3, io2):
                assert _marker(out, f"EBS-SERIAL-{vid}") == vid.replace("-", ""), (
                    f"the guest device behind {_dev(vid)} is not {vid}: stdout={out!r}"
                )
                assert _marker(out, f"EBS-RC-{vid}") == "0", f"dd to {vid} failed: stdout={out!r}"
                assert int(_marker(out, f"EBS-W-{vid}") or 0) == w_bytes, (
                    f"round {n}: the guest did not write {w_bytes} bytes to {vid}: stdout={out!r}"
                )

        def _view():
            end = _now() + datetime.timedelta(minutes=1)
            return {(v, m): _series(cw, v, m, start, end) for v in (gp3, io2)
                    for m in ("VolumeWriteBytes",) + _IO2_ONLY}

        def _total(view, v, m):
            return sum(p["Sum"] for p in view[(v, m)])

        seen = {}
        for n in (1, 2):
            if n == 2:
                # The second round must land in a LATER bucket than every first-round datapoint, so
                # it is a second published round rather than more bytes folded into the first.
                last = max(p["Timestamp"] for pts in seen.values() for p in pts)
                _poll(dl, _now, lambda t: _minute(t) > last, cap_s=90, interval_s=2.0,
                      what=f"the clock passing the last first-round bucket {last.isoformat()}")
            _write_round(n)
            dl.log(f"round {n} written")
            seen = _poll(
                dl, _view,
                lambda v: _total(v, gp3, "VolumeWriteBytes") >= n * w_bytes
                and _total(v, io2, "VolumeWriteBytes") >= n * w_bytes
                and all(len(v[(io2, m)]) >= n for m in _IO2_ONLY),
                cap_s=240, interval_s=10.0,
                what=(f"round {n}: VolumeWriteBytes >= {n * w_bytes} for both volumes and the io2 "
                      f"volume {io2} publishing {_IO2_ONLY!r} in >= {n} bucket(s)"))
            dl.log({f"{v}:{m}": [(p["Timestamp"].isoformat(), p["Sum"]) for p in pts]
                    for (v, m), pts in seen.items()})
            assert _total(seen, io2, "VolumeConsumedReadWriteOps") > 0, (
                f"io2 volume {io2} published VolumeConsumedReadWriteOps of zero after round {n}: "
                f"{seen[(io2, 'VolumeConsumedReadWriteOps')]!r}"
            )
            for m in _IO2_ONLY:
                assert seen[(gp3, m)] == [], (
                    f"round {n}: gp3 volume {gp3} published the io2-only metric {m} "
                    f"{seen[(gp3, m)]!r}, while its own VolumeWriteBytes "
                    f"({_total(seen, gp3, 'VolumeWriteBytes')!r}) and the io2 volume's {m} show the "
                    "pipeline delivering for the same write"
                )
        assert dl.left() >= 0, f"the check overran its {_DEADLINE_S}s deadline: {dl.elapsed():.0f}s"
        dl.log("done")
    finally:
        own.unwind()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
