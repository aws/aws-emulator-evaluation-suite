"""session-resume-within-timeout-succeeds."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-resume-within-timeout-succeeds"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ssm"]

_INSTANCE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResumeSession called well before the session's idle timeout elapses reconnects the
    same session id successfully and the session remains visible as Active."""
    ssm = ctx.client("ssm")
    instance_id = _create_ssm_managed_instance(ctx)

    # No per-session idleSessionTimeout override: real AWS only honors that value through the
    # account's Session Manager preferences document (Owner=Self, name literally
    # "SSM-SessionManagerRunShell"), not through StartSession's Parameters -- confirmed on real
    # AWS, where StartSession(..., DocumentName="SSM-SessionManagerRunShell", Parameters=...)
    # fails with InvalidDocument (that name resolves to nothing until a preferences document is
    # created) and passing Parameters without a DocumentName fails with InvalidParameters
    # ("idleSessionTimeout" is not a parameter of the implicit default document). That preferences
    # document is an account-global singleton shared by every concurrent session in the account/
    # region, so creating or mutating it here would change idle-timeout behavior for every other
    # check running concurrently. AWS's own default idle timeout (20 minutes) is already "well
    # before" this check's own resume, which happens within seconds of starting the session.
    start = ssm.start_session(Target=instance_id)
    session_id = start["SessionId"]

    def _safe_terminate() -> None:
        try:
            ssm.terminate_session(SessionId=session_id)
        except ClientError as err:
            # TerminateSession is idempotent; only a session the service no longer knows is skipped.
            if err.response["Error"]["Code"] != "DoesNotExistException":
                raise

    ctx.on_cleanup(_safe_terminate)

    def _active_probe() -> list[dict[str, Any]]:
        resp = ssm.describe_sessions(
            State="Active", Filters=[{"key": "SessionId", "value": session_id}]
        )
        return resp.get("Sessions", [])

    _poll_until(_active_probe, lambda s: len(s) == 1, timeout_s=60.0, interval_s=5.0)

    resume = ssm.resume_session(SessionId=session_id)
    assert resume["SessionId"] == session_id, (
        f"ResumeSession must return the same SessionId {session_id!r}, got "
        f"{resume['SessionId']!r}"
    )
    assert resume.get("TokenValue"), "ResumeSession did not return a renewal TokenValue"
    assert resume.get("StreamUrl"), "ResumeSession did not return a StreamUrl"

    # The session must still be reported active (not terminated) right after resuming -- an
    # independent read through describe_sessions, not the resume call's own response.
    still_active = _active_probe()
    assert len(still_active) == 1 and still_active[0]["SessionId"] == session_id, (
        f"expected exactly 1 Active session {session_id!r} after resume, got {still_active!r}"
    )
    assert still_active[0].get("Status") != "Terminated", (
        f"session {session_id!r} reported Terminated immediately after a successful resume"
    )


# ===== helpers =====


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 120.0,
    interval_s: float = 5.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_ssm_managed_instance(ctx) -> str:
    """Launch a t3.micro EC2 instance with an SSM-managed-instance role and wait until its
    SSM Agent registers Online. Registers full teardown (instance, profile, role)."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssmrole-")
    trust = json.dumps(
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_INSTANCE_ROLE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_INSTANCE_ROLE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-ssmprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-ssm-behav-")
    instance_id = None
    last_err: Exception | None = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and instance_id is None:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterCombination",
            ):
                raise
            time.sleep(5)
    if instance_id is None:
        raise AssertionError(f"could not launch SSM-managed instance: {last_err}")

    def _terminate_and_wait() -> None:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_terminate_and_wait)

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    def _ping_probe() -> dict[str, Any] | None:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        return infos[0] if infos else None

    _poll_until(
        _ping_probe,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=420.0,
        interval_s=10.0,
    )
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
