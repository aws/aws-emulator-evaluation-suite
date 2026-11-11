"""ec2-concurrent-attach-of-one-volume-to-two-instances-yields-a-single-winner."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-concurrent-attach-of-one-volume-to-two-instances-yields-a-single-winner"
GROUP = 'concurrency'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
ERR_VOLUME_IN_USE = 'VolumeInUse'
RACERS = 4
DATA_GIB = 1
DATA_BYTES = DATA_GIB * 1024 * 1024 * 1024
#: How long each guest waits for a device of exactly DATA_BYTES before reporting SIM2REAL-NODISK.
#: The three losers' reports are the effect-absent half of the check, so this has to be long enough
#: that a slow attach cannot be read as an absence.
GUEST_WAIT_S = 300

# ===== helpers (self-contained) =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last observation: {last!r}"
    )


def _ssm_ami(ctx, parameter=AL2023_SSM):
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_azs(ctx, instance_type=INSTANCE_TYPE):
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable


def _default_subnet(ctx, az):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        {"Name": "availability-zone", "Values": [az]},
    ])["Subnets"]
    if not subnets:
        raise AssertionError(f"account has no network subnet in {az}")
    return subnets[0]["SubnetId"]


def _run_instances(ctx, *, ami, subnet_id, user_data, scenario, count,
                   instance_type=INSTANCE_TYPE):
    """One RunInstances for all `count` racers, so they are placed and booted together."""
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}]
    resp = ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=count, MaxCount=count,
        SubnetId=subnet_id, UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
        ],
    )
    return [i["InstanceId"] for i in resp["Instances"]]


def _instance_state(ctx, instance_id):
    ec2 = ctx.client("ec2")
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ctx, instance_ids, timeout_s=600):
    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=list(instance_ids))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if all(_instance_state(ctx, i) in ("terminated", "__gone__") for i in instance_ids):
            return
        time.sleep(5)


def _create_volume(ctx, az, scenario, size_gib=DATA_GIB):
    ec2 = ctx.client("ec2")
    return ec2.create_volume(
        AvailabilityZone=az, Size=size_gib, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["VolumeId"]


def _describe_volume(ctx, volume_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _delete_volume_when_free(ctx, volume_id, timeout_s=420):
    ec2 = ctx.client("ec2")
    try:
        ec2.detach_volume(VolumeId=volume_id, Force=True)
    except ClientError as exc:
        if _code(exc) not in ("IncorrectState", "InvalidVolume.NotFound"):
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return
            # A volume still detaching is refused as in use until the detach completes.
            if _code(exc) not in ("VolumeInUse", "IncorrectState") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _console(ctx, instance_id):
    """The instance's serial console text, AS RETURNED by GetConsoleOutput(Latest=True).

    Latest=True is required on Nitro instance types. Output is not decoded here: botocore's
    ``decode_console_output`` handler already base64-decodes it in place (and leaves it untouched
    when it is not valid base64), so decoding again turns the guest's own words into binary noise.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or ""


def _guest_verdict(text):
    """'disk <name> <bytes>', 'nodisk', or None if the guest has not reported yet.

    Sliced AT the marker rather than from either end of the line, because /dev/console is shared
    with the login getty. On AWS a guest report arrives
    as ``'ip-172-31-36-148 login: SIM2REAL-DISK nvme1n1 1073741824'``.
    """
    for ln in reversed(text.splitlines()):
        parts = ln.strip().split()
        if "SIM2REAL-NODISK" in parts:
            return "nodisk"
        if "SIM2REAL-DISK" in parts:
            i = parts.index("SIM2REAL-DISK")
            if len(parts) >= i + 3:
                return f"disk {parts[i + 1]} {parts[i + 2]}"
    return None


def _guest_script(wait_s=GUEST_WAIT_S):
    """User data that reports whether a device of exactly DATA_BYTES ever appears, found by SIZE via
    lsblk rather than by a device path: nitro exposes /dev/nvme1n1 where xen exposes /dev/xvdf.

    The NEGATIVE report is what the three losers contribute, so the script always says something.
    """
    return (
        "#!/bin/bash\n"
        f"for i in $(seq 1 {wait_s // 3}); do\n"
        f"  LINE=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {DATA_BYTES} {{print $1, $2; exit}}')\n"
        '  if [ -n "$LINE" ]; then echo "SIM2REAL-DISK $LINE" > /dev/console; exit 0; fi\n'
        "  sleep 3\n"
        "done\n"
        'echo "SIM2REAL-NODISK" > /dev/console\n'
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Four simultaneous AttachVolume calls for one volume to four instances yield exactly one
    success and three VolumeInUse refusals, one attachment, and a device visible in exactly one
    guest: single-winner arbitration, confirmed inside the guests rather than only in the API."""
    ec2 = ctx.client("ec2")
    scenario = "ec2-concurrent-attach-one-winner"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    subnet_id = _default_subnet(ctx, az)

    instance_ids = _run_instances(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                                  count=RACERS, user_data=_guest_script())
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_ids))
    assert len(instance_ids) == RACERS, (
        f"RunInstances returned {len(instance_ids)} instances, expected {RACERS}: {instance_ids!r}"
    )
    _poll_until(lambda: [_instance_state(ctx, i) for i in instance_ids],
                lambda states: all(s == "running" for s in states),
                timeout_s=900, interval_s=10,
                description=f"all {RACERS} racers reach 'running'")

    volume_id = _create_volume(ctx, az, scenario)
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, volume_id))
    _poll_until(lambda: _describe_volume(ctx, volume_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=5,
                description=f"volume {volume_id} reaches 'available'")

    # --- the race: one volume, four instances, four threads, one call each ---
    def _attach(instance_id):
        try:
            return instance_id, ec2.attach_volume(
                VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")["State"], None, None
        except ClientError as exc:
            return instance_id, None, _code(exc), exc.response.get("Error", {}).get("Message")

    with concurrent.futures.ThreadPoolExecutor(max_workers=RACERS) as pool:
        results = list(pool.map(_attach, instance_ids))

    successes = [(i, state) for i, state, code, _ in results if code is None]
    codes = [code for _, _, code, _ in results if code is not None]
    messages = [message for _, _, code, message in results if code is not None]

    assert len(successes) == 1, (
        f"exactly ONE of {RACERS} simultaneous AttachVolume calls for {volume_id} may succeed, got "
        f"{len(successes)}: successes={successes!r} refusals={codes!r}"
    )
    assert len(codes) == RACERS - 1, (
        f"the other {RACERS - 1} calls must be refused, got {len(codes)}: {codes!r}"
    )
    assert set(codes) == {ERR_VOLUME_IN_USE}, (
        f"every refusal must be exactly {ERR_VOLUME_IN_USE!r}; the observed set was {set(codes)!r} "
        f"over {codes!r}"
    )
    assert messages == [f"{volume_id} is already attached to an instance"] * (RACERS - 1), messages
    winner = successes[0][0]

    # --- the API's view: one attachment, and it names the winner ---
    attachments = _poll_until(
        lambda: _describe_volume(ctx, volume_id)["Attachments"],
        lambda at: bool(at) and at[0]["State"] == "attached", timeout_s=300, interval_s=5,
        description=f"volume {volume_id} settles as 'attached' on the winner {winner}")
    assert len(attachments) == 1, (
        f"a volume may carry exactly one attachment, DescribeVolumes reports {attachments!r}"
    )
    assert attachments[0]["InstanceId"] == winner, (
        f"the attachment names {attachments[0]['InstanceId']!r} but the winning AttachVolume call "
        f"was for {winner!r}"
    )

    # --- the guests' view: the device is on exactly one of the four machines ---
    verdicts = _poll_until(
        lambda: {i: _guest_verdict(_console(ctx, i)) for i in instance_ids},
        lambda v: all(x is not None for x in v.values()),
        timeout_s=900, interval_s=20,
        description=f"all {RACERS} guests report whether a {DATA_GIB} GiB device appeared")

    assert verdicts[winner].startswith("disk "), (
        f"the winner {winner} attached the volume but its guest reports {verdicts[winner]!r} — the "
        f"attachment did not reach the machine. All verdicts: {verdicts!r}"
    )
    assert verdicts[winner].split()[2] == str(DATA_BYTES), (
        f"the winner's guest sees a device of {verdicts[winner]!r}, expected {DATA_BYTES} bytes"
    )
    losers = {i: v for i, v in verdicts.items() if i != winner}
    assert set(losers.values()) == {"nodisk"}, (
        f"the {RACERS - 1} refused instances must see NO {DATA_GIB} GiB device; their guests "
        f"reported {losers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
