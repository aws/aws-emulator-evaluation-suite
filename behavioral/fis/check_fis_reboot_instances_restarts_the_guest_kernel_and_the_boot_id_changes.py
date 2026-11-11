"""fis-reboot-instances-restarts-the-guest-kernel-and-the-boot-id-changes."""
from __future__ import annotations

import json
import re
import time
import uuid

from behavioral_harness import tags

CHECK = "fis-reboot-instances-restarts-the-guest-kernel-and-the-boot-id-changes"
GROUP = "fault-injection"
SERVICES = ["fis"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_EC2_ACCESS_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AWSFaultInjectionSimulatorEC2Access"
)
_MARKER_RE = re.compile(r"SIM2REAL_BOOT (\S+) ([0-9a-f-]{36}) (\d+)")
# A real second boot writes a whole kernel + cloud-init log. Measured: 10,002 NEW console bytes
# between the first and the second marker.
_MIN_NEW_CONSOLE_BYTES = 500
# A printk timestamp prefix -- `[    6.096338] `. GetConsoleOutput truncates each boot's log to
# roughly its last 10 KB, so the `Linux version` banner printed at [0.000000] is not retrievable;
# counting printk prefixes is truncation-proof and is what a synthesized marker line cannot produce.
_KERNEL_TIMESTAMP_RE = re.compile(r"\[\s*\d+\.\d{6}\]")
_MIN_KERNEL_TIMESTAMPS = 20
_CLOUD_INIT_MARKER = "cloud-init["

# On AWS the first console marker appears ~32 s after instance_running, the experiment completes
# well inside 300 s and the second marker appears ~42 s after StartExperiment; each deadline below
# is a large multiple of that.
_FIRST_BOOT_CONSOLE_TIMEOUT_S = 600.0
_EXPERIMENT_TIMEOUT_S = 600.0
_SECOND_BOOT_CONSOLE_TIMEOUT_S = 900.0
_STATUS_OK_TIMEOUT_S = 900.0
_TERMINATE_TIMEOUT_S = 600.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """A FIS aws:ec2:reboot-instances experiment really restarts the guest: the serial console shows
    a new kernel boot_id and a root-volume boot counter of 2, while the same instance keeps its
    LaunchTime (a reboot, not a stop/start onto a fresh volume or a relaunch)."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    fis = ctx.client("fis")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    nonce = uuid.uuid4().hex
    # cloud-init `bootcmd` runs on EVERY boot (`runcmd` runs only on the first), so the marker is
    # written again by the reboot. The counter lives on the root volume, and /dev/console is what
    # GetConsoleOutput returns -- so the guest needs no network egress and no instance profile.
    user_data = (
        "#cloud-config\n"
        "bootcmd:\n"
        "  - [ sh, -c, 'F=/var/lib/sim2real_boots; N=$(cat $F 2>/dev/null || echo 0); "
        "N=$((N+1)); echo $N > $F; echo \"SIM2REAL_BOOT " + nonce +
        " $(cat /proc/sys/kernel/random/boot_id) $N\" > /dev/console' ]\n"
    )

    ami = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    zone = _usable_zone(ec2, ctx=ctx)
    subnet = _default_subnet(ec2, zone, ctx=ctx)

    instance = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet, UserData=user_data,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-g1-reboot-")},
            {"Key": "sim2real", "Value": "g1-fault-injection"}]}],
    )["Instances"][0]
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_quiet(ec2, instance_id))

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    described = _describe(ec2, instance_id)
    launch_time_before = described["LaunchTime"]

    console_before, markers_before = _poll_console_markers(
        ec2, instance_id, want=1, timeout_s=_FIRST_BOOT_CONSOLE_TIMEOUT_S)
    assert len(markers_before) == 1, (
        f"the first boot wrote {len(markers_before)} SIM2REAL_BOOT markers, expected exactly 1: "
        f"{markers_before!r}"
    )
    boot_nonce, boot_id_before, counter_before = markers_before[0]
    assert boot_nonce == nonce, (
        f"console marker carried nonce {boot_nonce!r}, not this run's {nonce!r} -- the console "
        "buffer belongs to another instance"
    )
    assert counter_before == "1", (
        f"the first boot's counter was {counter_before!r}, expected '1'"
    )
    uuid.UUID(boot_id_before)  # raises ValueError if the kernel's boot_id is not a real UUID

    # ---- the FIS rig -----------------------------------------------------------------------------
    # The target names the instance by explicit resourceArns, never resourceTags: a tag-scoped
    # reboot target could reboot another instance in the same account.
    role_arn, role_name = _create_fis_role(ctx, iam, account, ctx.region)
    instance_arn = f"arn:aws:ec2:{ctx.region}:{account}:instance/{instance_id}"
    template_id = _create_template(
        ctx, fis, role_arn=role_arn,
        targets={"rebootTarget": {"resourceType": "aws:ec2:instance",
                                  "resourceArns": [instance_arn],
                                  "selectionMode": "ALL"}},
        actions={"reboot": {"actionId": "aws:ec2:reboot-instances",
                            "targets": {"Instances": "rebootTarget"}}},
    )
    experiment_id = _start_experiment(ctx, fis, template_id)

    final = _poll_experiment(fis, experiment_id, {"completed", "stopped", "failed"},
                             timeout_s=_EXPERIMENT_TIMEOUT_S)
    assert final == "completed", (
        f"the reboot experiment ended as {final!r}, expected 'completed'"
    )
    action_state = fis.get_experiment(id=experiment_id)["experiment"]["actions"]["reboot"]["state"]
    assert action_state["status"] == "completed", (
        f"the reboot action's own state was {action_state!r}, expected status 'completed'"
    )
    assert "skip" not in action_state.get("reason", "").lower(), (
        f"the action's reason says it was skipped: {action_state!r} -- no reboot was attempted"
    )

    # FIS resolved exactly this instance as the experiment's target.
    resolved = fis.list_experiment_resolved_targets(experimentId=experiment_id)["resolvedTargets"]
    assert len(resolved) == 1, f"expected exactly 1 resolved target, got {resolved!r}"
    assert instance_id in " ".join(resolved[0]["targetInformation"].values()), (
        f"the resolved target does not name our instance: {resolved[0]['targetInformation']!r}"
    )

    # ---- the guest's own evidence that it really rebooted ---------------------------------------
    console_after, markers_after = _poll_console_markers(
        ec2, instance_id, want=2, timeout_s=_SECOND_BOOT_CONSOLE_TIMEOUT_S)
    assert len(markers_after) == 2, (
        f"after the reboot experiment the console holds {len(markers_after)} SIM2REAL_BOOT "
        f"markers, expected 2 -- the guest never booted a second time: {markers_after!r}"
    )
    assert markers_after[0] == markers_before[0], (
        f"the first boot's marker changed from {markers_before[0]!r} to {markers_after[0]!r} -- the "
        "console buffer was replaced rather than appended to"
    )
    _, boot_id_after, counter_after = markers_after[1]
    uuid.UUID(boot_id_after)
    assert boot_id_after != boot_id_before, (
        f"/proc/sys/kernel/random/boot_id was {boot_id_after!r} both times -- the kernel did not "
        "re-seed, so it never restarted"
    )
    assert counter_after == "2", (
        f"the second boot's counter was {counter_after!r}, expected '2' -- the counter file on the "
        "root volume did not survive, so this was not a reboot but a fresh volume"
    )

    grew_by = len(console_after) - len(console_before)
    assert grew_by >= _MIN_NEW_CONSOLE_BYTES, (
        f"the console buffer grew by only {grew_by} bytes across the reboot, expected at least "
        f"{_MIN_NEW_CONSOLE_BYTES} -- a synthesized marker, not a real boot's console log"
    )
    first_marker_at = console_after.index("SIM2REAL_BOOT")
    second_marker_at = console_after.index("SIM2REAL_BOOT", first_marker_at + 1)
    between = console_after[first_marker_at:second_marker_at]
    printks = _KERNEL_TIMESTAMP_RE.findall(between)
    assert len(printks) >= _MIN_KERNEL_TIMESTAMPS, (
        f"only {len(printks)} printk timestamp prefixes appear between the two boot markers "
        f"({len(between)} bytes), expected at least {_MIN_KERNEL_TIMESTAMPS} -- no kernel log was "
        f"produced. Tail was {between[-400:]!r}"
    )
    assert _CLOUD_INIT_MARKER in between, (
        f"the {len(between)} bytes between the two boot markers contain no "
        f"{_CLOUD_INIT_MARKER!r} line -- the guest's init system did not run again"
    )

    # ---- the reboot was a reboot, not a re-launch -------------------------------------------------
    described_after = _describe(ec2, instance_id)
    assert described_after["InstanceId"] == instance_id, (
        f"instance id changed to {described_after['InstanceId']!r}"
    )
    assert described_after["LaunchTime"] == launch_time_before, (
        f"LaunchTime moved from {launch_time_before!r} to {described_after['LaunchTime']!r} -- the "
        "instance was RELAUNCHED, not rebooted"
    )
    assert described_after["State"]["Name"] == "running", (
        f"after the reboot the instance is {described_after['State']['Name']!r}, expected 'running'"
    )

    # ---- and it came back healthy -----------------------------------------------------------------
    status = _poll_status_ok(ec2, instance_id, timeout_s=_STATUS_OK_TIMEOUT_S)
    assert status == ("ok", "ok"), (
        f"after the reboot the status checks settled at {status!r}, expected ('ok', 'ok')"
    )

    # ---- verified inline teardown -----------------------------------------------------------------
    fis.delete_experiment_template(id=template_id)
    gone, gone_message = _error(lambda: fis.get_experiment_template(id=template_id))
    assert gone == "ResourceNotFoundException", (
        f"after DeleteExperimentTemplate, GetExperimentTemplate reported {gone!r}"
    )
    assert gone_message == "ExperimentTemplate not found.", (
        f"after DeleteExperimentTemplate, GetExperimentTemplate said {gone_message!r}"
    )
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id],
        WaiterConfig={"Delay": 2, "MaxAttempts": int(_TERMINATE_TIMEOUT_S // 2)})
    assert _describe(ec2, instance_id)["State"]["Name"] == "terminated", (
        "the instance did not reach 'terminated'"
    )
    iam.detach_role_policy(RoleName=role_name, PolicyArn=_EC2_ACCESS_POLICY)
    iam.delete_role(RoleName=role_name)
    role_gone, role_gone_message = _error(lambda: iam.get_role(RoleName=role_name))
    assert role_gone == "NoSuchEntity", (
        f"after DeleteRole, GetRole reported {role_gone!r}, expected 'NoSuchEntity'"
    )
    expected_role_gone = f"The role with name {role_name} cannot be found."
    assert role_gone_message == expected_role_gone, (
        f"after DeleteRole, GetRole said {role_gone_message!r}, expected {expected_role_gone!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises AssertionError: a target accepting a call real AWS refuses must never be mistaken
    for a falsy code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _describe(ec2, instance_id):
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def _usable_zone(ec2, *, ctx):
    """Intersect the AZs that are AVAILABLE with the AZs that offer the instance type."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}, {"Name": "location", "Values": ctx.network().availability_zones}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ offers {_INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _default_subnet(ec2, zone, *, ctx):
    subnets = []
    for page in ec2.get_paginator("describe_subnets").paginate(
            Filters=[{"Name": "availability-zone", "Values": [zone]},
                     {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]):
        subnets.extend(page["Subnets"])
    assert subnets, f"no network subnet in {zone!r}"
    return subnets[0]["SubnetId"]


def _terminate_quiet(ec2, instance_id):
    from botocore.exceptions import ClientError

    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _poll_console_markers(ec2, instance_id, want, timeout_s):
    deadline = time.monotonic() + timeout_s
    output = ""
    markers = []
    while time.monotonic() < deadline:
        output = ec2.get_console_output(InstanceId=instance_id, Latest=True).get("Output", "")
        markers = _MARKER_RE.findall(output)
        if len(markers) >= want:
            return output, markers
        time.sleep(2)
    raise AssertionError(
        f"only {len(markers)} SIM2REAL_BOOT markers on the console after {timeout_s}s, wanted "
        f"{want}; the console held {len(output)} bytes"
    )


def _poll_status_ok(ec2, instance_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        statuses = ec2.describe_instance_status(InstanceIds=[instance_id])["InstanceStatuses"]
        if statuses:
            last = (statuses[0]["InstanceStatus"]["Status"],
                    statuses[0]["SystemStatus"]["Status"])
            if last == ("ok", "ok"):
                return last
        time.sleep(2)
    return last


def _create_fis_role(ctx, iam, account, region):
    name = ctx.unique_name("sim2real-g1-fisrole-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"},
                       "Action": "sts:AssumeRole",
                       "Condition": {
                           "StringEquals": {"aws:SourceAccount": account},
                           "ArnLike": {"aws:SourceArn":
                                       f"arn:aws:fis:{region}:{account}:experiment/*"}}}]}),
        Tags=[{"Key": "sim2real", "Value": "g1-fault-injection"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _iam_quiet(lambda: iam.delete_role(RoleName=name)))
    iam.attach_role_policy(RoleName=name, PolicyArn=_EC2_ACCESS_POLICY)
    ctx.on_cleanup(lambda: _iam_quiet(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_EC2_ACCESS_POLICY)))
    return arn, name


def _iam_quiet(fn):
    """Run an IAM teardown call; the run body already deletes the role, so NoSuchEntity is done."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_template(ctx, fis, role_arn, targets, actions, timeout_s=180.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            template_id = fis.create_experiment_template(
                clientToken=ctx.unique_name("sim2real-g1-tok-"),
                description=ctx.unique_name("sim2real-g1-reboot-"),
                stopConditions=[{"source": "none"}],
                targets=targets, actions=actions, roleArn=role_arn,
                tags={"sim2real": "g1-fault-injection"},
            )["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: _delete_template_quiet(fis, template_id))
            return template_id
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(3)
    raise AssertionError(f"CreateExperimentTemplate never succeeded in {timeout_s}s (last {last!r})")


def _delete_template_quiet(fis, template_id):
    from botocore.exceptions import ClientError

    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _start_experiment(ctx, fis, template_id, timeout_s=180.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            experiment_id = fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-g1-start-"),
                experimentTemplateId=template_id,
                tags={"sim2real": "g1-fault-injection"},
            )["experiment"]["id"]
            ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))
            return experiment_id
        except ClientError as err:
            last = err.response["Error"]["Code"]
            time.sleep(4)
    raise AssertionError(f"StartExperiment never succeeded in {timeout_s}s (last {last!r})")


def _stop_experiment_quiet(fis, experiment_id):
    from botocore.exceptions import ClientError

    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


def _poll_experiment(fis, experiment_id, stop_on, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if last in stop_on:
            return last
        time.sleep(3)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
