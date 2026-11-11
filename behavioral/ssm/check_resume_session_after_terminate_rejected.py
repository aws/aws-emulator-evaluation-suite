"""resume-session-after-terminate-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resume-session-after-terminate-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResumeSession on a terminated session fails with ValidationException instead of reviving it,
    and no Active session reappears; resuming the same session while active succeeds."""
    instance_id = _provision_connected_target(ctx)
    ssm = ctx.client("ssm")

    started = ssm.start_session(Target=instance_id)
    session_id = started["SessionId"]
    ctx.on_cleanup(lambda: _best_effort_terminate(ssm, session_id))

    # Positive control: resuming a still-ACTIVE session succeeds and returns fresh
    # stream connection details.
    resumed = ssm.resume_session(SessionId=session_id)
    assert resumed["SessionId"] == session_id, (
        f"positive-control ResumeSession returned SessionId {resumed.get('SessionId')!r}, "
        f"expected {session_id!r}"
    )
    assert resumed.get("TokenValue"), "positive-control ResumeSession returned no TokenValue"
    assert resumed.get("StreamUrl"), "positive-control ResumeSession returned no StreamUrl"

    ssm.terminate_session(SessionId=session_id)
    history = _poll_until(
        lambda: _find_session(ssm, "History", session_id),
        lambda s: s is not None and s.get("Status") == "Terminated",
        timeout_s=120,
        interval_s=5,
    )
    assert history is not None, "session never reached Terminated -- cannot test post-terminate resume"

    code, message = _client_error(
        lambda: ssm.resume_session(SessionId=session_id),
        on_unexpected_success=lambda resp: ctx.on_cleanup(
            lambda: _best_effort_terminate(ssm, resp["SessionId"])
        ),
    )
    # AWS answers ValidationException here, not the DoesNotExistException the API reference implies.
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Session is not in a valid state", f"unexpected message {message!r}"

    # Effect absent: no Active session for this id was resurrected by the failed resume.
    active = ssm.describe_sessions(
        State="Active", Filters=[{"key": "SessionId", "value": session_id}]
    )["Sessions"]
    assert not [s for s in active if s["SessionId"] == session_id], (
        "rejected ResumeSession must not leave an Active session behind"
    )


def _best_effort_terminate(ssm, session_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ssm.terminate_session(SessionId=session_id)
    except ClientError as err:
        # A session the service no longer knows, or one run() already terminated, is done.
        error = err.response["Error"]
        if error["Code"] == "DoesNotExistException":
            return
        if (error["Code"], error.get("Message")) != (
            "ValidationException", "Session is not in a valid state"
        ):
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


def _client_error(fn, *, on_unexpected_success=None):
    """Call fn(); return the botocore error (code, message), raising if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
