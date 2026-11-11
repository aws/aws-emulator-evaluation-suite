"""connection-status-tracks-session-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-status-tracks-session-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetConnectionStatus reports agent readiness, not session state: it stays "connected"
    before, during and after a Session Manager session on an online managed node.
    """
    ssm = ctx.client("ssm")
    instance_id = _launch_managed_instance(ctx)

    pre_session = _poll_until(
        lambda: ssm.get_connection_status(Target=instance_id)["Status"],
        lambda status: status == "connected",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert pre_session == "connected", f"expected connected before StartSession, got {pre_session}"

    start_resp = ssm.start_session(Target=instance_id)
    session_id = start_resp["SessionId"]
    ctx.on_cleanup(lambda: _terminate_session_quiet(ssm, session_id))

    during_session = ssm.get_connection_status(Target=instance_id)["Status"]
    assert during_session == "connected", (
        f"expected connected while the Session Manager session is active, got {during_session}"
    )

    ssm.terminate_session(SessionId=session_id)

    active_sessions = _poll_until(
        lambda: ssm.describe_sessions(
            State="Active", Filters=[{"key": "Target", "value": instance_id}]
        )["Sessions"],
        lambda sessions: not any(s["SessionId"] == session_id for s in sessions),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert not any(s["SessionId"] == session_id for s in active_sessions), (
        f"session {session_id} still listed Active 60s after TerminateSession"
    )

    after_termination = ssm.get_connection_status(Target=instance_id)["Status"]
    assert after_termination == "connected", (
        "connection status flipped to notconnected merely because the session "
        "ended, even though the managed node's SSM Agent is still online"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _terminate_session_quiet(ssm, session_id: str) -> None:
    try:
        ssm.terminate_session(SessionId=session_id)
    except ClientError as err:
        # A session the service does not know, or one already terminated, needs no teardown.
        error = err.response["Error"]
        terminated = "Session is not in a valid state" in error.get("Message", "")
        if error["Code"] == "ValidationException" and terminated:
            return
        if error["Code"] != "DoesNotExistException":
            raise


def _default_subnet_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    return subnets[0]["SubnetId"] if subnets else None


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _launch_managed_instance(ctx) -> str:
    """Launch a t3.micro EC2 instance with an SSM-managed-instance IAM profile and
    wait for it to register with SSM (PingStatus=Online)."""

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if not subnet_id:
        raise AssertionError(
            "no default VPC/subnet available to launch a test managed-instance EC2 host"
        )

    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    role_name = ctx.unique_name("sim2real-ssm-mi-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    profile_name = ctx.unique_name("sim2real-ssm-mi-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except ClientError:
            time.sleep(2)

    ami_id = _latest_al2023_ami(ctx)
    tag_name = ctx.unique_name("sim2real-ssm-mi-")

    instance_id = None
    launch_deadline = time.monotonic() + 60
    last_error: Exception | None = None
    while time.monotonic() < launch_deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": tag_name}]}
                ],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            last_error = exc
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            time.sleep(3)
    if instance_id is None:
        raise AssertionError(f"could not launch test instance: {last_error}")

    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    online_deadline = time.monotonic() + 480
    online = False
    while time.monotonic() < online_deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            online = True
            break
        time.sleep(2)
    if not online:
        raise AssertionError(
            f"EC2 instance {instance_id} did not register as an SSM managed node within "
            "8 minutes (agent bootstrap or outbound network egress issue in this environment)"
        )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
