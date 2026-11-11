"""e2e-session-manager-connect-use-history-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-session-manager-connect-use-history-flow"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSession, GetConnectionStatus 'connected', then TerminateSession moves the session from
    DescribeSessions' Active state to its History state."""
    ssm = ctx.client("ssm")
    instance_id = _provision_ssm_managed_instance(ctx)

    session = ssm.start_session(Target=instance_id)
    session_id = session["SessionId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.terminate_session(SessionId=session_id)))

    status = _poll_until(
        lambda: ssm.get_connection_status(Target=instance_id)["Status"],
        lambda s: s == "connected",
        timeout_s=60,
        interval_s=3,
    )
    assert status == "connected", f"expected managed instance connected before StartSession, got {status!r}"

    active_ids = _poll_until(
        lambda: [s["SessionId"] for s in ssm.describe_sessions(State="Active")["Sessions"]],
        lambda ids: session_id in ids,
        timeout_s=30,
        interval_s=3,
    )
    assert session_id in active_ids, (
        f"expected {session_id} in DescribeSessions(State=Active), got {active_ids}"
    )

    ssm.terminate_session(SessionId=session_id)

    history_ids = _poll_until(
        lambda: [s["SessionId"] for s in ssm.describe_sessions(State="History")["Sessions"]],
        lambda ids: session_id in ids,
        timeout_s=90,
        interval_s=5,
    )
    assert session_id in history_ids, (
        f"expected {session_id} in DescribeSessions(State=History) after TerminateSession, got {history_ids}"
    )

    active_after = [s["SessionId"] for s in ssm.describe_sessions(State="Active")["Sessions"]]
    assert session_id not in active_after, (
        f"expected {session_id} removed from DescribeSessions(State=Active) after TerminateSession, still present in {active_after}"
    )


# Teardown steps return only when the resource is already gone; any other failure raises.
_NOT_FOUND = ("DoesNotExistException", "NoSuchEntity", "InvalidInstanceID.NotFound")
# TerminateSession on a session run() already terminated is refused with exactly this error.
_ALREADY_TERMINATED = ("ValidationException", "Session is not in a valid state")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] in _NOT_FOUND:
            return
        if (error["Code"], error.get("Message")) != _ALREADY_TERMINATED:
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _ssm_ami_id(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _provision_ssm_managed_instance(ctx, timeout_s: float = 420.0) -> str:
    """Launch an EC2 instance with the AmazonSSMManagedInstanceCore role and wait until it registers
    Online with SSM; registers cleanup for the instance, profile and role."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssm-role-")
    profile_name = ctx.unique_name("sim2real-ssm-prof-")
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role() -> None:
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)

    iam.create_instance_profile(InstanceProfileName=profile_name)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    def _cleanup_profile() -> None:
        _safe(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        )
        _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    ctx.on_cleanup(_cleanup_profile)

    ami_id = _ssm_ami_id(ctx)
    name_tag = ctx.unique_name("sim2real-ssm-node-")
    instance_id = None
    last_err = None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValue":
                time.sleep(5)
                continue
            raise
    if instance_id is None:
        raise AssertionError(f"could not launch instance with IAM profile: {last_err}")

    def _cleanup_instance() -> None:
        _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
        _safe(lambda: ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}))

    ctx.on_cleanup(_cleanup_instance)

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    def _ping_status():
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp["InstanceInformationList"]
        return infos[0]["PingStatus"] if infos else None

    status = _poll_until(_ping_status, lambda s: s == "Online", timeout_s=timeout_s, interval_s=15)
    if status != "Online":
        raise AssertionError(f"managed instance {instance_id} never reached Online ping status")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
