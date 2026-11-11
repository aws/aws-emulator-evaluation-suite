"""hibernate-guest-process-and-its-in-memory-value-survive-the-resume."""
from __future__ import annotations

import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hibernate-guest-process-and-its-in-memory-value-survive-the-resume"
GROUP = "hibernation-data-plane"
SERVICES = ["ec2"]

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: The type this row exists to measure. Hibernation needs a supporting instance family, and the
#: memory image is written to the ROOT volume, so the type decides both the RAM to preserve and the
#: root size needed to hold it. m5.large also has no local NVMe, which matters here: there is no
#: ephemeral disk on the machine for the guest's value to have hidden on.
_INSTANCE_TYPE = "m5.large"
_REASON_HIBERNATE = "Client.UserInitiatedHibernate"
_HOLDER = "/usr/local/bin/sim2real-holder.sh"
#: Both live on tmpfs, which is RAM: they are therefore off the root device and invisible to the
#: `find / -xdev` search below, by construction rather than by an exclusion list.
_REVEAL = "/dev/shm/sim2real-reveal"
_PIDFILE = "/dev/shm/sim2real-holder.pid"

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


def _retry_delete(fn, retries=24, delay=5.0):
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
                              "InvalidAssociationID.NotFound", "Gateway.NotAttached"):
                return None
            raise


def _usable_az(ec2, itype):
    """The AZ catalogue intersection, asserted rather than guessed.

    Both halves are load-bearing. `describe_instance_type_offerings` does not report zone STATE, so
    an impaired zone still appears as offering the type; `describe_availability_zones` says nothing
    about instance types. A literal AZ name is not the fix either — AZ names are per-account aliases
    for different physical zones. An empty intersection means this region cannot run the check.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [itype]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no AZ this region reports as available offers {itype!r}; offerings were "
        f"{sorted(offered)!r}. This region cannot run the check."
    )
    return usable[0]


def _public_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with a public subnet in `az`.

    Deliberately not the account's default VPC: a fresh account need not have one, and a shared
    default subnet makes the check assert a property of the account. The
    SSM agent needs egress to reach its endpoint, so the subnet gets an internet gateway, a default
    route and auto-assigned public addressing. Every piece is tagged at creation — an untagged VPC
    object cannot be found for cleanup.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
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
    return subnet


def _instance_profile(ctx, iam, scenario):
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-hib-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav hibernation data-plane role",
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


def _describe(ec2, instance_id):
    """The instance, or None once it is gone. Tolerates the post-RunInstances 404 window."""
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _instance_state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', not merely 'shutting-down': the ENI and the instance
    profile association only clear at the end, and the subnet/VPC teardown registered earlier
    cannot proceed until they do."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _newest_al2023(ec2, ssm):
    """The current AL2023 x86_64 AMI, its root device name and the smallest root it permits."""
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 x86_64 parameter did not resolve to an AMI: {ami!r}"
    img = ec2.describe_images(ImageIds=[ami])["Images"][0]
    root_gib = max((b["Ebs"]["VolumeSize"] for b in img["BlockDeviceMappings"] if "Ebs" in b),
                   default=8)
    return ami, img["RootDeviceName"], root_gib


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=600):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted (or just been
    resumed from hibernation) rejects SendCommand with InvalidInstanceId until its agent has
    registered, so retrying that call polls an observable condition instead of sleeping a guessed
    interval. A host that never accepts a command is a FAIL — 'the machine did not come back' is the
    fidelity defect this check exists to catch, not an environment limitation.
    """
    deadline = time.monotonic() + ready_timeout_s
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav hibernation data plane",
            )
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
    """The `key=value` fields of the last line starting with `marker`, as a dict.

    The guest emits one machine-readable line per phase, so nothing here depends on the order or
    the wording of the rest of its output.
    """
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


def _hibernate_when_ready(ec2, instance_id, timeout_s=900, interval_s=15.0):
    """StopInstances(Hibernate=True), retried past the post-launch not-ready-yet refusal.

    Real AWS answers `UnsupportedOperation` with "not ready to hibernate yet" for a window after
    launch, while the in-guest agent reserves its swap space, and exposes NO queryable readiness
    field — so that one specific, deterministic refusal is the negative outcome of a bounded poll
    rather than a sleep. Any other error, and a window that never closes, is a failure.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return ec2.stop_instances(InstanceIds=[instance_id], Hibernate=True)
        except ClientError as exc:
            last = exc
            if _code(exc) != "UnsupportedOperation":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{instance_id} never accepted StopInstances(Hibernate=True) within "
                    f"{timeout_s}s; the last refusal was {last.response.get('Error')!r}"
                ) from last
            time.sleep(interval_s)


#: The process the check grades. It receives the value in its ENVIRONMENT and never writes it to
#: the root filesystem: the only copy is anonymous memory until a SIGUSR1 copies it to tmpfs, which
#: is RAM. Nothing in this text is the value, so the script file itself carries no secret — and the
#: holder reports its own `$$` rather than the caller reading `$!`, which after `setsid` need not be
#: the pid of the surviving process.
_HOLDER_SRC = "\n".join([
    f"cat > {_HOLDER} <<'EOS'",
    "#!/bin/bash",
    "# V arrives in the environment and is never written to the root filesystem.",
    f"echo $$ > {_PIDFILE}",
    f"trap 'printf \"%s\" \"$V\" > {_REVEAL}' USR1",
    "while true; do sleep 1; done",
    "EOS",
    f"chmod 755 {_HOLDER}",
])

#: Signal the holder, wait for the tmpfs copy to appear, and take its digest. Only the DIGEST is
#: ever printed, so the 32 raw bytes never leave the guest — which is what makes the on-disk search
#: a search for something the check has never transmitted and could not recognise.
_REVEAL_SH = "\n".join([
    f"rm -f {_REVEAL}",
    'kill -USR1 "$PID"',
    f"for _ in $(seq 1 30); do [ -s {_REVEAL} ] && break; sleep 1; done",
    f'if [ ! -s {_REVEAL} ]; then echo "HOLDER-DID-NOT-REVEAL"; exit 1; fi',
    f"DIGEST=$(sha256sum {_REVEAL} | cut -d' ' -f1)",
])

#: Field 22 of /proc/<pid>/stat is starttime in clock ticks since boot, immutable for the life of
#: the process — which is what tells THIS process apart from a recycled pid. Read after dropping
#: everything up to the last ')', because field 2 is the comm and may contain spaces.
_PROC_FACTS = "\n".join([
    "START=$(sed 's/.*) //' /proc/$PID/stat | awk '{print $20}')",
    'CMD=$(tr -d "\\000" < /proc/$PID/cmdline)',
])

# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """Hibernating an m5.large and starting it again restores the same process (pid, start time, cmdline)
    under the same boot_id, still holding a random value that existed only in its memory and never on the
    root device."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "hibernate-guest-memory-survives-resume"

    # --- everything decidable, before anything is created ---------------------
    info = ec2.describe_instance_types(InstanceTypes=[_INSTANCE_TYPE])["InstanceTypes"]
    assert info, f"{_INSTANCE_TYPE} is not offered in {ctx.region}"
    assert info[0].get("HibernationSupported") is True, (
        f"{_INSTANCE_TYPE} reports HibernationSupported {info[0].get('HibernationSupported')!r}; "
        f"this check needs a type that can hibernate"
    )
    assert info[0].get("InstanceStorageSupported") is False, (
        f"{_INSTANCE_TYPE} reports InstanceStorageSupported "
        f"{info[0].get('InstanceStorageSupported')!r}; the point of this type is that the guest has "
        f"no ephemeral disk on which the value could have survived"
    )
    mem_gib = math.ceil(info[0]["MemoryInfo"]["SizeInMiB"] / 1024)
    az = _usable_az(ec2, _INSTANCE_TYPE)
    ami, root_device, ami_gib = _newest_al2023(ec2, ssm)
    # Room for the whole of RAM plus the installed system, so an undersized root cannot be what AWS
    # objects to. Derived from the type's own MemoryInfo, never a constant.
    root_gib = max(ami_gib, mem_gib * 2 + 20)

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    # --- one hibernation-enabled instance ------------------------------------
    tag_spec = [
        {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": profile},
                                      {"Key": "sim2real", "Value": scenario}]}
        for rt in ("instance", "volume")
    ]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            IamInstanceProfile={"Name": profile}, TagSpecifications=tag_spec,
            HibernationOptions={"Configured": True},
            BlockDeviceMappings=[{"DeviceName": root_device,
                                  "Ebs": {"Encrypted": True, "VolumeSize": root_gib,
                                          "VolumeType": "gp3", "DeleteOnTermination": True}}],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0].get("HibernationOptions") == {"Configured": True}, (
        f"the launch was meant to be hibernation-enabled, but RunInstances reported "
        f"{reservation['Instances'][0].get('HibernationOptions')!r}"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")

    # The precondition holds on the live estate, not merely in the request we sent.
    inst = _describe(ec2, instance_id)
    root_vol = next(b["Ebs"]["VolumeId"] for b in inst["BlockDeviceMappings"]
                    if b["DeviceName"] == root_device)
    vol = ec2.describe_volumes(VolumeIds=[root_vol])["Volumes"][0]
    assert vol["Encrypted"] is True and vol["Size"] >= mem_gib, (
        f"hibernation needs an encrypted root with room for {mem_gib} GiB of RAM; the root volume "
        f"{root_vol} came back as {vol!r}"
    )

    # --- the agent must register: a host that never registers is a FAIL -------
    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for i in page["InstanceInformationList"]:
                if i.get("InstanceId") == instance_id:
                    return i
        return None

    agent = _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                  timeout_s=600, interval_s=5.0,
                  what=f"the SSM agent on {instance_id} coming Online")
    assert agent["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {agent.get('PlatformType')!r}"
    )

    # --- phase 1: a process holding 32 random bytes it never writes to disk ----
    start_holder = [
        "set -euo pipefail",
        _HOLDER_SRC,
        f"rm -f {_PIDFILE} {_REVEAL}",
        # Generated INSIDE the guest: the check never sees or sends the raw bytes.
        "V=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \\n')",
        "export V",
        f"setsid nohup {_HOLDER} >/dev/null 2>&1 </dev/null &",
        "unset V",
        f"for _ in $(seq 1 20); do [ -s {_PIDFILE} ] && break; sleep 1; done",
        f'if [ ! -s {_PIDFILE} ]; then echo "HOLDER-NEVER-STARTED"; exit 1; fi',
        f"PID=$(cat {_PIDFILE})",
        'if ! kill -0 "$PID"; then echo "HOLDER-NOT-RUNNING"; exit 1; fi',
        _PROC_FACTS,
        _REVEAL_SH,
        # The bytes must be nowhere on the EBS root. -xdev keeps the walk on the root device, so
        # every tmpfs — including the reveal file being used as the pattern — is out of scope.
        "ONDISK=$( { find / -xdev -type f -print0 2>/dev/null"
        f" | xargs -0 -r grep -lF -f {_REVEAL} 2>/dev/null || true; }} | wc -l )",
        f"rm -f {_REVEAL}",
        f'if [ -e {_REVEAL} ]; then echo "REVEAL-NOT-CLEARED"; exit 1; fi',
        'echo "SIM2REAL-HOLD pid=$PID start=$START digest=$DIGEST ondisk=$ONDISK cmd=$CMD'
        ' boot=$(cat /proc/sys/kernel/random/boot_id)"',
    ]
    first = _report(_run_guest(ssm, instance_id, start_holder,
                               "starting the in-memory holder process"), "SIM2REAL-HOLD")
    assert first and first.get("pid") and first.get("digest") and first.get("boot"), (
        f"the guest did not report a running holder process; it said {first!r}"
    )
    assert first["ondisk"] == "0", (
        f"the value the holder is holding was found in {first['ondisk']} file(s) on the EBS root "
        f"device, so its survival across the hibernate would prove nothing about RAM; the guest "
        f"reported {first!r}"
    )
    assert first["cmd"].endswith(_HOLDER), (
        f"the holder's cmdline must name {_HOLDER!r} so a recycled pid cannot impersonate it later; "
        f"the guest reported cmd={first['cmd']!r}"
    )
    pid, start_ticks, digest, boot0 = (first["pid"], first["start"], first["digest"], first["boot"])

    # --- phase 2: hibernate ---------------------------------------------------
    stopping = _hibernate_when_ready(ec2, instance_id)
    assert stopping["StoppingInstances"][0]["InstanceId"] == instance_id, (
        f"StopInstances(Hibernate=True) answered about a different instance: {stopping!r}"
    )
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "stopped",
          timeout_s=900, interval_s=10.0,
          what=f"instance {instance_id} reaching 'stopped' after hibernating")
    stopped = _describe(ec2, instance_id)
    assert (stopped.get("StateReason") or {}).get("Code") == _REASON_HIBERNATE, (
        f"a hibernation must record StateReason {_REASON_HIBERNATE!r}, not "
        f"{stopped.get('StateReason')!r} — a plain stop reports Client.UserInitiatedShutdown, and "
        f"writes no memory image for the assertions below to grade"
    )

    # --- phase 3: start it again, and ask the guest ---------------------------
    _call_with_retry(lambda: ec2.start_instances(InstanceIds=[instance_id]))
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=900, interval_s=10.0,
          what=f"instance {instance_id} returning to 'running' after the hibernate")

    after_resume = [
        "set -uo pipefail",
        f"PID={pid}",
        'if ! kill -0 "$PID" 2>/dev/null; then',
        '  echo "SIM2REAL-RESUME alive=no pid=$PID start=- digest=- cmd=-'
        ' boot=$(cat /proc/sys/kernel/random/boot_id)"; exit 0;',
        "fi",
        _PROC_FACTS,
        "set -e",
        _REVEAL_SH,
        f"rm -f {_REVEAL}",
        'echo "SIM2REAL-RESUME alive=yes pid=$PID start=$START digest=$DIGEST cmd=$CMD'
        ' boot=$(cat /proc/sys/kernel/random/boot_id)"',
    ]
    second = _report(_run_guest(ssm, instance_id, after_resume,
                                "interrogating the guest after the resume"), "SIM2REAL-RESUME")
    assert second, "the guest produced no SIM2REAL-RESUME line after the resume"

    # The five in-guest facts, ordered so that a failure reads as the thing that went wrong.
    assert second["boot"] == boot0, (
        f"hibernation reloads the RAM image, so the kernel's boot_id must be UNCHANGED across the "
        f"resume: it was {boot0!r} before and is {second['boot']!r} now, which means the guest "
        f"cold-booted and no memory image was restored"
    )
    assert second["alive"] == "yes", (
        f"the holder process (pid {pid}) must still be running after the resume; the guest reported "
        f"{second!r}"
    )
    assert second["start"] == start_ticks, (
        f"pid {pid} is running but started at {second['start']!r} rather than {start_ticks!r}, so it "
        f"is a DIFFERENT process wearing a recycled pid, not the one that was hibernated"
    )
    assert second["cmd"].endswith(_HOLDER), (
        f"pid {pid} is running but its cmdline is {second['cmd']!r}, not {_HOLDER!r}"
    )
    assert second["digest"] == digest, (
        f"the surviving process revealed {second['digest']!r} after the resume but {digest!r} "
        f"before it: it came back without the memory it was holding, which is exactly what "
        f"hibernation must not do"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
