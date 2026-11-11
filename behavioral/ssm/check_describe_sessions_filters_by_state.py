"""describe-sessions-filters-by-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-sessions-filters-by-state"
GROUP = "state-machine"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSessions(State=Active) surfaces an in-progress session and NOT a terminated
    one; after TerminateSession the same session disappears from Active and appears under
    State=History with a terminal Status."""
    instance_id = _provision_connected_target(ctx)
    ssm = ctx.client("ssm")

    start_resp = ssm.start_session(Target=instance_id)
    session_id = start_resp["SessionId"]
    ctx.on_cleanup(lambda: _best_effort_terminate(ssm, session_id))

    active_hit = _poll_until(
        lambda: _find_session(ssm, "Active", session_id),
        lambda s: s is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert active_hit is not None, "started session never appeared under DescribeSessions Active"

    # While it is still active, it must NOT be listed under History.
    assert _find_session(ssm, "History", session_id) is None, (
        "an active session must not already appear under DescribeSessions History"
    )

    ssm.terminate_session(SessionId=session_id)

    history_hit = _poll_until(
        lambda: _find_session(ssm, "History", session_id),
        lambda s: s is not None and s.get("Status") == "Terminated",
        timeout_s=120,
        interval_s=5,
    )
    assert history_hit is not None, "terminated session never appeared under DescribeSessions History"
    assert history_hit["Status"] == "Terminated", (
        f"expected Status=Terminated for the History entry, got {history_hit['Status']!r}"
    )

    # It must no longer be reported as Active.
    still_active = _poll_until(
        lambda: _find_session(ssm, "Active", session_id),
        lambda s: s is None,
        timeout_s=60,
        interval_s=3,
    )
    assert still_active is None, "terminated session is still listed under DescribeSessions Active"


def _best_effort_terminate(ssm, session_id: str) -> None:
    from botocore.exceptions import ClientError

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


def _find_session(ssm, state: str, session_id: str):
    resp = ssm.describe_sessions(
        State=state, Filters=[{"key": "SessionId", "value": session_id}]
    )
    for session in resp.get("Sessions", []):
        if session["SessionId"] == session_id:
            return session
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


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
