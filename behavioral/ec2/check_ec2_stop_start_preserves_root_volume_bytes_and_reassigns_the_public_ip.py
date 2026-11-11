"""ec2-stop-start-preserves-root-volume-bytes-and-reassigns-the-public-ip."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-stop-start-preserves-root-volume-bytes-and-reassigns-the-public-ip"
GROUP = 'instance-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'

# ===== helpers =====


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
    """A network subnet in az, asserted to auto-assign a public IPv4 address on launch — the check's
    third assertion is about that address, so the property must be established, not assumed."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        {"Name": "availability-zone", "Values": [az]},
    ])["Subnets"]
    if not subnets:
        raise AssertionError(f"account has no network subnet in {az}")
    subnet = subnets[0]
    assert subnet["MapPublicIpOnLaunch"] is True, (
        f"shared-network subnet {subnet['SubnetId']} does not auto-assign public IPv4 "
        f"(MapPublicIpOnLaunch={subnet['MapPublicIpOnLaunch']!r}), so there is no auto-assigned "
        f"address for this check to watch"
    )
    return subnet["SubnetId"]


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE, **kw):
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}]
    return ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
        ],
        **kw,
    )["Instances"][0]


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


def _terminate_and_wait(ctx, instance_id, timeout_s=600):
    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ctx, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _describe_instance_paginated(ctx, instance_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id} not found in any page of DescribeInstances")


def _root_volume_id(inst):
    root = inst["RootDeviceName"]
    for bdm in inst.get("BlockDeviceMappings", []):
        if bdm["DeviceName"] == root:
            return bdm["Ebs"]["VolumeId"]
    raise AssertionError(
        f"instance {inst['InstanceId']} exposes no BlockDeviceMappings entry for its own root "
        f"device {root!r}: {inst.get('BlockDeviceMappings')!r}"
    )


def _console(ctx, instance_id):
    """The instance's serial console text, AS RETURNED by GetConsoleOutput(Latest=True).

    Latest=True is required on Nitro instance types. Output is not decoded here: botocore's
    ``decode_console_output`` handler already base64-decodes it in place (and leaves it untouched
    when it is not valid base64), so decoding again turns the guest's own words into binary noise.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or ""


def _boot_reports(text):
    """{sequence-number: reported-nonce} over every SIM2REAL-BOOT line in the console text.

    The console buffer is NOT cleared by a stop/start, so keying the post-restart wait on the nonce
    alone would match the PRE-STOP output and pass vacuously. The guest therefore emits a boot
    SEQUENCE number it persists on the root filesystem, and this parses on that.
    """
    out = {}
    for ln in text.splitlines():
        if "SIM2REAL-BOOT" not in ln:
            continue
        parts = ln.strip().split()
        i = parts.index("SIM2REAL-BOOT")
        if len(parts) >= i + 3:
            out[parts[i + 1]] = parts[i + 2]
    return out


def _guest_script(nonce):
    """User data that writes a nonce to the root filesystem and installs a systemd unit which, on
    EVERY boot, increments a persisted counter and re-echoes the file's contents with that counter.

    The counter is what makes the post-restart observation falsifiable, and /var/lib is used rather
    than /var/tmp because systemd-tmpfiles is entitled to clean the latter.
    """
    return (
        "#!/bin/bash\n"
        "mkdir -p /var/lib/sim2real\n"
        f'printf "%s\\n" "{nonce}" > /var/lib/sim2real/nonce.txt\n'
        "cat > /usr/local/bin/sim2real-boot.sh <<'EOS'\n"
        "#!/bin/bash\n"
        "SEQ=$(cat /var/lib/sim2real/seq 2>/dev/null || echo 0)\n"
        "SEQ=$((SEQ + 1))\n"
        "echo $SEQ > /var/lib/sim2real/seq\n"
        "sync\n"
        "echo \"SIM2REAL-BOOT $SEQ $(cat /var/lib/sim2real/nonce.txt)\" > /dev/console\n"
        "EOS\n"
        "chmod +x /usr/local/bin/sim2real-boot.sh\n"
        "cat > /etc/systemd/system/sim2real-boot.service <<'EOS'\n"
        "[Unit]\n"
        "Description=sim2real boot reporter\n"
        "After=local-fs.target\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/local/bin/sim2real-boot.sh\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        "EOS\n"
        "systemctl daemon-reload\n"
        "systemctl enable sim2real-boot.service\n"
        "/usr/local/bin/sim2real-boot.sh\n"
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stop/start cycle preserves the root filesystem's bytes, the private IPv4, the instance id and the
    root volume id, while the auto-assigned public IPv4 changes (it is released on stop)."""
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ec2-stop-start-conservation"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    subnet_id = _default_subnet(ctx, az)

    instance_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                                user_data=_guest_script(nonce))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"instance {instance_id} reaches 'running'")

    before_text = _poll_until(lambda: _console(ctx, instance_id),
                              lambda t: "1" in _boot_reports(t),
                              timeout_s=900, interval_s=15,
                              description=f"instance {instance_id} reports boot sequence 1")
    first = _boot_reports(before_text)
    assert first["1"] == nonce, (
        f"the first boot reported nonce {first['1']!r}, expected {nonce!r}"
    )

    before = _poll_until(lambda: _describe_instance_paginated(ctx, instance_id),
                         lambda i: bool(i.get("PublicIpAddress")), timeout_s=300, interval_s=5,
                         description=f"instance {instance_id} has an auto-assigned public address")
    private_before = before["PrivateIpAddress"]
    public_before = before["PublicIpAddress"]
    root_before = _root_volume_id(before)

    # --- stop ---
    ec2.stop_instances(InstanceIds=[instance_id])
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "stopped",
                timeout_s=900, interval_s=10,
                description=f"instance {instance_id} reaches 'stopped'")
    stopped = _describe_instance_paginated(ctx, instance_id)
    reason = stopped.get("StateTransitionReason", "")
    assert reason, (
        f"a stopped instance must report why it left 'running'; StateTransitionReason was "
        f"{reason!r}"
    )
    assert stopped.get("PublicIpAddress") is None, (
        f"a stopped instance must not still hold an auto-assigned public address, got "
        f"{stopped.get('PublicIpAddress')!r} (it had {public_before!r} while running)"
    )

    # --- start, and the SECOND boot re-reads the file the FIRST boot wrote ---
    ec2.start_instances(InstanceIds=[instance_id])
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=900, interval_s=10,
                description=f"instance {instance_id} returns to 'running'")
    after_text = _poll_until(lambda: _console(ctx, instance_id),
                             lambda t: "2" in _boot_reports(t),
                             timeout_s=900, interval_s=15,
                             description=f"instance {instance_id} reports boot sequence 2")
    second = _boot_reports(after_text)
    assert second["2"] == nonce, (
        f"the second boot read {second['2']!r} out of the root filesystem where the first boot "
        f"wrote {nonce!r} — the root volume did not survive the stop/start"
    )

    after = _poll_until(lambda: _describe_instance_paginated(ctx, instance_id),
                        lambda i: bool(i.get("PublicIpAddress")), timeout_s=300, interval_s=5,
                        description=f"instance {instance_id} has a public address again")

    # --- conserved: the private address, the machine, and its root disk ---
    assert after["PrivateIpAddress"] == private_before, (
        f"the private IPv4 address must be conserved across a stop/start; it was "
        f"{private_before!r} and is now {after['PrivateIpAddress']!r}"
    )
    assert after["InstanceId"] == instance_id, (
        f"the instance id changed across the stop/start: {instance_id!r} -> "
        f"{after['InstanceId']!r} — a restart must not replace the machine"
    )
    root_after = _root_volume_id(after)
    assert root_after == root_before, (
        f"the root volume id changed across the stop/start: {root_before!r} -> {root_after!r}"
    )

    # --- NOT conserved: the auto-assigned public address is released on stop ---
    assert after["PublicIpAddress"] != public_before, (
        f"an auto-assigned public IPv4 address is released on stop, so the restarted instance must "
        f"answer to a DIFFERENT address; it reported {after['PublicIpAddress']!r} both before and "
        f"after (was {public_before!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
