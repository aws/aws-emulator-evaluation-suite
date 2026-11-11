"""ec2-instance-type-change-is-visible-to-the-guest-and-matches-the-catalog."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-instance-type-change-is-visible-to-the-guest-and-matches-the-catalog"
GROUP = 'instance-data-plane'
SERVICES = ['ec2']

SMALL_TYPE = 't3.micro'
#: t3.micro and t3.large both declare 2 vCPUs, so the pair must reach t3.xlarge for DefaultVCpus to
#: differ at all — a same-vCPU pair would make the load-bearing assertion vacuous.
LARGE_TYPE = 't3.xlarge'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
#: The guest never sees the nominal figure: firmware, the kernel and its reserved regions take a
#: cut, and that cut is a LARGER FRACTION on a small instance. On real AWS a t3.micro reports
#: MemTotal 913 MiB against a declared 1024 MiB, i.e. 89.2%, so a 0.90 floor false-FAILs. The floor is therefore 0.85, and it is only a sanity
#: bracket: the load-bearing assertions are the EXACT nproc equality against DefaultVCpus and the
#: STRICT inequality between the two boots' MemTotal.
MEM_MARGIN_LOW = 0.85

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


def _azs_offering_both(ctx, *instance_types):
    """AZ names that are 'available' AND offer every one of instance_types.

    The resize would otherwise fail 'Unsupported' in a zone that offers the small type but not the
    large one, which reads exactly like a fidelity failure.
    """
    ec2 = ctx.client("ec2")
    per_type = []
    for t in instance_types:
        per_type.append({o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [t]}],
        )["InstanceTypeOfferings"]})
    offered = set.intersection(*per_type)
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers all of {instance_types!r}; the per-type offerings "
        f"were {[sorted(s) for s in per_type]!r}"
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


def _type_catalog(ctx, instance_type):
    """(DefaultVCpus, MemoryInfo.SizeInMiB) as DescribeInstanceTypes declares them."""
    infos = []
    for page in ctx.client("ec2").get_paginator("describe_instance_types").paginate(
            InstanceTypes=[instance_type]):
        infos += page["InstanceTypes"]
    assert len(infos) == 1, (
        f"DescribeInstanceTypes({instance_type!r}) returned {len(infos)} entries: {infos!r}"
    )
    return infos[0]["VCpuInfo"]["DefaultVCpus"], infos[0]["MemoryInfo"]["SizeInMiB"]


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type, **kw):
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
        f"instance {inst['InstanceId']} exposes no BlockDeviceMappings entry for its root device "
        f"{root!r}: {inst.get('BlockDeviceMappings')!r}"
    )


def _console(ctx, instance_id):
    """The instance's serial console text, AS RETURNED by GetConsoleOutput(Latest=True).

    Latest=True is required on Nitro instance types. Output is not decoded here: botocore's
    ``decode_console_output`` handler already base64-decodes it in place (and leaves it untouched
    when it is not valid base64), so decoding again turns the guest's own words into binary noise.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or ""


def _hw_reports(text):
    """{boot-sequence: (nproc, MemTotal-in-kB)} over every SIM2REAL-HW line in the console text.

    Keyed on a persisted boot SEQUENCE rather than on the values, because GetConsoleOutput's buffer
    survives a stop/start: a post-resize wait keyed on the values alone could match the FIRST
    boot's line and pass vacuously.
    """
    out = {}
    for ln in text.splitlines():
        if "SIM2REAL-HW" not in ln:
            continue
        parts = ln.strip().split()
        i = parts.index("SIM2REAL-HW")
        if len(parts) >= i + 4 and parts[i + 2].isdigit() and parts[i + 3].isdigit():
            out[parts[i + 1]] = (int(parts[i + 2]), int(parts[i + 3]))
    return out


def _guest_script():
    """User data installing a systemd unit that, on EVERY boot, reports the machine's own CPU count
    and MemTotal alongside a persisted boot sequence number."""
    return (
        "#!/bin/bash\n"
        "mkdir -p /var/lib/sim2real\n"
        "cat > /usr/local/bin/sim2real-hw.sh <<'EOS'\n"
        "#!/bin/bash\n"
        "SEQ=$(cat /var/lib/sim2real/seq 2>/dev/null || echo 0)\n"
        "SEQ=$((SEQ + 1))\n"
        "echo $SEQ > /var/lib/sim2real/seq\n"
        "sync\n"
        "MEM=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)\n"
        'echo "SIM2REAL-HW $SEQ $(nproc) $MEM" > /dev/console\n'
        "EOS\n"
        "chmod +x /usr/local/bin/sim2real-hw.sh\n"
        "cat > /etc/systemd/system/sim2real-hw.service <<'EOS'\n"
        "[Unit]\n"
        "Description=sim2real hardware reporter\n"
        "After=local-fs.target\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/local/bin/sim2real-hw.sh\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
        "EOS\n"
        "systemctl daemon-reload\n"
        "systemctl enable sim2real-hw.service\n"
        "/usr/local/bin/sim2real-hw.sh\n"
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After ModifyInstanceAttribute changes a stopped instance's type and it restarts, the guest's own CPU
    count and memory match DescribeInstanceTypes' VCpuInfo and MemoryInfo for the new type, and did not before."""
    ec2 = ctx.client("ec2")
    scenario = "ec2-resize-visible-to-guest"

    small_cpus, small_mib = _type_catalog(ctx, SMALL_TYPE)
    large_cpus, large_mib = _type_catalog(ctx, LARGE_TYPE)
    assert small_cpus != large_cpus, (
        f"the check needs two types whose DefaultVCpus DIFFER, but {SMALL_TYPE} declares "
        f"{small_cpus} and {LARGE_TYPE} declares {large_cpus} — the guest-side assertion would be "
        f"vacuous"
    )
    assert large_mib > small_mib, (
        f"{LARGE_TYPE} declares {large_mib} MiB which is not more than {SMALL_TYPE}'s {small_mib} MiB"
    )

    ami = _ssm_ami(ctx)
    az = _azs_offering_both(ctx, SMALL_TYPE, LARGE_TYPE)[0]
    subnet_id = _default_subnet(ctx, az)

    instance_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                                instance_type=SMALL_TYPE,
                                user_data=_guest_script())["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"instance {instance_id} reaches 'running' as {SMALL_TYPE}")

    before_text = _poll_until(lambda: _console(ctx, instance_id),
                              lambda t: "1" in _hw_reports(t), timeout_s=900, interval_s=15,
                              description=f"instance {instance_id} reports its first-boot hardware")
    boot1_cpus, boot1_mem_kb = _hw_reports(before_text)["1"]
    launched = _describe_instance_paginated(ctx, instance_id)
    root_before = _root_volume_id(launched)

    assert boot1_cpus == small_cpus, (
        f"the guest counted {boot1_cpus!r} CPUs on its first boot but DescribeInstanceTypes "
        f"declares DefaultVCpus={small_cpus!r} for {SMALL_TYPE} — the catalogue does not describe "
        f"the machine that booted"
    )
    boot1_mem_mib = boot1_mem_kb // 1024
    assert small_mib * MEM_MARGIN_LOW <= boot1_mem_mib <= small_mib, (
        f"the guest reported MemTotal {boot1_mem_mib} MiB, outside the firmware-reserved band "
        f"[{small_mib * MEM_MARGIN_LOW:.0f}, {small_mib}] MiB that DescribeInstanceTypes declares "
        f"for {SMALL_TYPE}"
    )

    # --- resize the stopped machine ---
    ec2.stop_instances(InstanceIds=[instance_id])
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "stopped",
                timeout_s=900, interval_s=10,
                description=f"instance {instance_id} reaches 'stopped'")
    ec2.modify_instance_attribute(InstanceId=instance_id, InstanceType={"Value": LARGE_TYPE})
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceType")
    assert attr["InstanceType"]["Value"] == LARGE_TYPE, (
        f"DescribeInstanceAttribute reports instanceType {attr['InstanceType']['Value']!r} after "
        f"the modify, expected {LARGE_TYPE!r}"
    )

    ec2.start_instances(InstanceIds=[instance_id])
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=900, interval_s=10,
                description=f"instance {instance_id} returns to 'running' as {LARGE_TYPE}")
    after_text = _poll_until(lambda: _console(ctx, instance_id),
                             lambda t: "2" in _hw_reports(t), timeout_s=900, interval_s=15,
                             description=f"instance {instance_id} reports its second-boot hardware")
    boot2_cpus, boot2_mem_kb = _hw_reports(after_text)["2"]

    # --- the guest is the witness: the machine that booted is the one the catalogue describes ---
    assert boot2_cpus == large_cpus, (
        f"after the resize the guest counted {boot2_cpus!r} CPUs but DescribeInstanceTypes declares "
        f"DefaultVCpus={large_cpus!r} for {LARGE_TYPE} (it counted {boot1_cpus!r} as {SMALL_TYPE}) "
        f"— the resize was accepted by the API but not performed on the machine"
    )
    boot2_mem_mib = boot2_mem_kb // 1024
    assert boot2_mem_mib > boot1_mem_mib, (
        f"after the resize the guest reports MemTotal {boot2_mem_mib} MiB, which is not more than "
        f"the {boot1_mem_mib} MiB it reported as {SMALL_TYPE}"
    )
    assert large_mib * MEM_MARGIN_LOW <= boot2_mem_mib <= large_mib, (
        f"the guest reported MemTotal {boot2_mem_mib} MiB, outside the firmware-reserved band "
        f"[{large_mib * MEM_MARGIN_LOW:.0f}, {large_mib}] MiB that DescribeInstanceTypes declares "
        f"for {LARGE_TYPE}"
    )

    # --- the resize did not replace the machine ---
    after = _describe_instance_paginated(ctx, instance_id)
    assert after["InstanceType"] == LARGE_TYPE, (
        f"DescribeInstances reports InstanceType {after['InstanceType']!r}, expected {LARGE_TYPE!r}"
    )
    assert after["InstanceId"] == instance_id, (
        f"the instance id changed across the resize: {instance_id!r} -> {after['InstanceId']!r}"
    )
    assert _root_volume_id(after) == root_before, (
        f"the root volume id changed across the resize: {root_before!r} -> "
        f"{_root_volume_id(after)!r} — a resize must not replace the machine's disk"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
