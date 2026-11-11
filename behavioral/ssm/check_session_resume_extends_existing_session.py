"""session-resume-extends-existing-session."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "session-resume-extends-existing-session"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResumeSession on a still-live session returns the SAME SessionId (no new session
    is created) with a fresh renewal token, rather than minting a second session."""
    instance_id = _provision_connected_target(ctx)
    ssm = ctx.client("ssm")

    start_resp = ssm.start_session(Target=instance_id)
    session_id = start_resp["SessionId"]
    ctx.on_cleanup(lambda: _best_effort_terminate(ssm, session_id))

    # Wait for the session to be reported Active before resuming it -- resuming a session
    # the control plane has not yet finished registering is a race, not a test of resume.
    _poll_until_active(ssm, session_id)

    resume_resp = ssm.resume_session(SessionId=session_id)

    assert resume_resp["SessionId"] == session_id, (
        "ResumeSession on an active session must return the SAME SessionId, "
        f"got {resume_resp['SessionId']!r} vs original {session_id!r}"
    )
    assert resume_resp["TokenValue"], "ResumeSession did not return a renewal TokenValue"
    assert resume_resp["StreamUrl"], "ResumeSession did not return a StreamUrl"

    # Exactly one Active session for this target -- resuming must not have spawned a second.
    active = ssm.describe_sessions(
        State="Active", Filters=[{"key": "SessionId", "value": session_id}]
    )["Sessions"]
    matching = [s for s in active if s["SessionId"] == session_id]
    assert len(matching) == 1, f"expected exactly 1 active session, found {len(matching)}"


def _best_effort_terminate(ssm, session_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ssm.terminate_session(SessionId=session_id)
    except ClientError as err:
        # TerminateSession is idempotent; only a session the service no longer knows is skipped.
        if err.response["Error"]["Code"] != "DoesNotExistException":
            raise


def _poll_until_active(ssm, session_id: str) -> None:
    deadline = time.monotonic() + 60.0
    last = []
    while time.monotonic() < deadline:
        last = ssm.describe_sessions(
            State="Active", Filters=[{"key": "SessionId", "value": session_id}]
        )["Sessions"]
        if len(last) == 1:
            return
        time.sleep(5)
    raise AssertionError(f"session {session_id} never reported Active (last={last!r})")


# ===== helpers =====
def _provision_connected_target(ctx) -> str:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch an
    EC2 instance, and wait until it registers Online with Systems Manager. Returns InstanceId."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-ssm-target-")

    instance_id = None
    last_err = None
    deadline = time.monotonic() + 90
    while instance_id is None and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
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
            instance_id = run_resp["Instances"][0]["InstanceId"]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(5)
    if instance_id is None:
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        if info and info[0].get("PingStatus") == "Online":
            return instance_id
        time.sleep(2)
    raise AssertionError(f"instance {instance_id} never reached SSM PingStatus=Online in time")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
