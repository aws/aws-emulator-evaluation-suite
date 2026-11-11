"""ssm-send-command-to-a-stopped-instance-rejected-and-no-invocation-is-created."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-send-command-to-a-stopped-instance-rejected-and-no-invocation-is-created"
GROUP = 'run-command'
SERVICES = ['ec2', 'ssm']

_MARKER = "sim2real-behav-runcmd-marker-6b21"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_STOPPED_MESSAGE = "Instances not in a valid state for account"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
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


def _usable_subnet(ec2, *, ctx):
    """A default-VPC public subnet in an AZ that both is available and offers the type."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers {_INSTANCE_TYPE}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r}"
    )
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert len(vpcs) == 1, f"expected exactly one shared network, got {vpcs!r}"
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    candidates = [
        s
        for s in subnets
        if s["AvailabilityZone"] in usable and s.get("MapPublicIpOnLaunch")
    ]
    assert candidates, (
        "the SSM agent must reach the SSM endpoint to register, so the instance needs a "
        f"public subnet in one of {usable!r}; the run's shared network offers "
        f"{[(s['SubnetId'], s['AvailabilityZone'], s.get('MapPublicIpOnLaunch')) for s in subnets]!r}"
    )
    return candidates[0]["SubnetId"], candidates[0]["AvailabilityZone"]


def _instance_state(ec2, instance_id):
    return [
        i["State"]["Name"]
        for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        for i in r["Instances"]
    ]


def _terminate_and_wait(ec2, instance_id, timeout_s=180):
    """Terminate and wait until the instance has left `running`/`stopped`, so the instance
    profile it references can then be deleted."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if all(s in ("shutting-down", "terminated") for s in _instance_state(ec2, instance_id)):
            return
        time.sleep(5)


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
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
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _commands_for(ssm, instance_id):
    """Every command SSM has recorded against this instance, fully paginated."""
    out = []
    for page in ssm.get_paginator("list_commands").paginate(InstanceId=instance_id):
        out += page["Commands"]
    return out


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """SendCommand to a registered but stopped instance is refused with InvalidInstanceId and
    records no command or invocation; the identical command succeeds before the stop and after a
    restart, so the refusal tracks instance state.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
    """

    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-stopcmd-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav stopped-instance run-command role",
        Tags=[{"Key": "sim2real", "Value": "send-command-stopped"}],
    )
    ctx.on_cleanup(lambda: _drop_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)

    profile_name = role_name
    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": "send-command-stopped"}],
    )
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, profile_name, role_name))
    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    subnet_id, zone = _usable_subnet(ec2, ctx=ctx)
    tag_spec = [
        {
            "ResourceType": rt,
            "Tags": [
                {"Key": "Name", "Value": role_name},
                {"Key": "sim2real", "Value": "send-command-stopped"},
            ],
        }
        for rt in ("instance", "volume")
    ]
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami,
            InstanceType=_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=tag_spec,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=30,
        delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    # Registered BEFORE the registration poll: a host that never comes up must not
    # be able to strand a billing instance.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == zone, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {zone!r}"
    )

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(
        _agent_view,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=300,
        interval_s=5.0,
        what=f"the SSM agent on {instance_id} coming Online",
    )
    assert info["PingStatus"] == "Online", f"instance {instance_id!r} is {info!r}"

    # --- POSITIVE CONTROL: the exact command that will later be refused -------
    script = [f"echo {_MARKER}"]
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": script},
            TimeoutSeconds=120,
            Comment="sim2real-behav positive control",
        )
    )
    control_command_id = sent["Command"]["CommandId"]

    def _invocation(cid):
        try:
            return ssm.get_command_invocation(CommandId=cid, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(
        lambda: _invocation(control_command_id),
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=180,
        interval_s=5.0,
        what=f"the control invocation {control_command_id} reaching a terminal status",
    )
    assert inv["Status"] == "Success", (
        "the control command on the RUNNING instance must succeed, else the refusal below "
        f"proves nothing; got {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["StandardOutputContent"].strip() == _MARKER, (
        f"the control command's stdout must be {_MARKER!r}, got "
        f"{inv['StandardOutputContent']!r}"
    )

    commands_before = _commands_for(ssm, instance_id)
    assert [c["CommandId"] for c in commands_before] == [control_command_id], (
        "exactly the control command must be recorded against this instance before the "
        f"refusal; got {[c['CommandId'] for c in commands_before]!r}"
    )

    # --- break exactly one thing: power the host off -------------------------
    _call_with_retry(lambda: ec2.stop_instances(InstanceIds=[instance_id]))
    _poll(
        lambda: _instance_state(ec2, instance_id),
        lambda states: states == ["stopped"],
        timeout_s=420,
        interval_s=10.0,
        what=f"{instance_id} reaching the stopped state",
    )

    # SSM must stop considering it a valid Run Command target. The agent's own
    # PingStatus is heartbeat-driven and lags, so poll the thing that is actually
    # claimed: that SendCommand refuses.
    def _send_to_stopped():
        try:
            resp = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=30,
                Comment="sim2real-behav stopped-instance probe",
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return (err.get("Code"), err.get("Message"))
        # Captured, not asserted inline: if SSM wrongly accepts it, the command
        # exists and the assertion below must be able to name it.
        return {"accepted": resp["Command"]["CommandId"]}

    outcome = _poll(
        _send_to_stopped,
        lambda o: not isinstance(o, dict),
        timeout_s=300,
        interval_s=15.0,
        what="SendCommand refusing a stopped instance",
    )
    assert outcome == ("InvalidInstanceId", _STOPPED_MESSAGE), (
        "SendCommand to a registered but STOPPED instance must be refused with "
        f"InvalidInstanceId and message {_STOPPED_MESSAGE!r}; got {outcome!r}"
    )

    # --- the effect is absent: no new command, no new invocation -------------
    commands_after = _commands_for(ssm, instance_id)
    assert [c["CommandId"] for c in commands_after] == [control_command_id], (
        "a refused SendCommand must record no command at all; ListCommands now holds "
        f"{[c['CommandId'] for c in commands_after]!r}, expected only "
        f"{[control_command_id]!r}"
    )
    invocations = []
    for page in ssm.get_paginator("list_command_invocations").paginate(
        InstanceId=instance_id, Details=True
    ):
        invocations += page["CommandInvocations"]
    assert [i["CommandId"] for i in invocations] == [control_command_id], (
        "a refused SendCommand must create no invocation; the instance now has "
        f"{[(i['CommandId'], i['Status']) for i in invocations]!r}"
    )

    # --- the control command's own record is untouched by the refusal --------
    still = ssm.get_command_invocation(
        CommandId=control_command_id, InstanceId=instance_id
    )
    assert still["Status"] == "Success", (
        f"the control invocation must still read Success, got {still['Status']!r}"
    )
    assert still["StandardOutputContent"].strip() == _MARKER, (
        f"the control invocation's stdout must be unchanged, got "
        f"{still['StandardOutputContent']!r}"
    )

    # --- and the instance is still there, merely stopped ---------------------
    assert _instance_state(ec2, instance_id) == ["stopped"], (
        "the refusal must not have been caused by the instance disappearing; state is "
        f"{_instance_state(ec2, instance_id)!r}"
    )
    # The instance must still be describable, so InvalidInstanceId is about eligibility.
    ec2.describe_instances(InstanceIds=[instance_id])

    # --- restore: restarting must restore eligibility, so InvalidInstanceId tracked the
    #     instance state rather than permanently banning this id ---------------------------
    _call_with_retry(lambda: ec2.start_instances(InstanceIds=[instance_id]))
    _poll(
        lambda: _instance_state(ec2, instance_id),
        lambda states: states == ["running"],
        timeout_s=180,
        interval_s=10.0,
        what=f"{instance_id} reaching the running state after restart",
    )
    info_again = _poll(
        _agent_view,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=300,
        interval_s=5.0,
        what=f"the SSM agent on {instance_id} coming back Online after restart",
    )
    assert info_again["PingStatus"] == "Online", f"instance {instance_id!r} is {info_again!r}"

    restored = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": script},
            TimeoutSeconds=120,
            Comment="sim2real-behav restored-instance control",
        )
    )
    restored_command_id = restored["Command"]["CommandId"]
    restored_inv = _poll(
        lambda: _invocation(restored_command_id),
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=180,
        interval_s=5.0,
        what=f"the restored invocation {restored_command_id} reaching a terminal status",
    )
    assert restored_inv["Status"] == "Success", (
        "the identical SendCommand call must succeed again once the instance is running, else "
        "the earlier refusal proved a permanent ban rather than a reachability check; got "
        f"{restored_inv['Status']!r}: {restored_inv.get('StatusDetails')!r} "
        f"stderr={restored_inv.get('StandardErrorContent')!r}"
    )
    assert restored_inv["StandardOutputContent"].strip() == _MARKER, (
        f"the restored command's stdout must be {_MARKER!r}, got "
        f"{restored_inv['StandardOutputContent']!r}"
    )

    # ListCommands documents no result order, so commands are ordered by RequestedDateTime.
    commands_final = sorted(_commands_for(ssm, instance_id), key=lambda c: c["RequestedDateTime"])
    assert [c["CommandId"] for c in commands_final] == [control_command_id, restored_command_id], (
        "after restart, ListCommands must hold exactly the control and the restored command, "
        f"requested in that order; expected {[control_command_id, restored_command_id]!r}, got "
        f"{[c['CommandId'] for c in commands_final]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
