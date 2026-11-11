"""resume-nonexistent-session-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resume-nonexistent-session-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResumeSession on a terminated session is rejected with ValidationException (not the
    DoesNotExistException the API reference implies) and the session stays out of Active,
    while ResumeSession on the same session succeeded while it was live."""
    instance_id = _provision_connected_target(ctx)
    ssm = ctx.client("ssm")

    start_resp = ssm.start_session(Target=instance_id)
    session_id = start_resp["SessionId"]
    ctx.on_cleanup(lambda: _best_effort_terminate(ssm, session_id))

    # Positive control: ResumeSession succeeds while the session is still live.
    control_resp = ssm.resume_session(SessionId=session_id)
    assert control_resp["SessionId"] == session_id, "positive-control ResumeSession failed"

    # Break exactly one thing: terminate the session.
    ssm.terminate_session(SessionId=session_id)
    _poll_until(
        lambda: _find_session(ssm, "History", session_id),
        lambda s: s is not None and s.get("Status") == "Terminated",
        timeout_s=120,
        interval_s=5,
    )

    code, message = _client_error(lambda: ssm.resume_session(SessionId=session_id))
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
    if predicate(value):
        return value
    raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
