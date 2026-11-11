"""session-resume-after-timeout-rejected."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-resume-after-timeout-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ssm"]

_INSTANCE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/session-preferences-timeout.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """ResumeSession on a session terminated by the idle timeout fails with ValidationException "Session is not in a
    valid state" and it stays Terminated, while a second session still inside its idle window resumes with a token
    and stream URL."""
    _require_session_plugin(ctx)
    ssm = ctx.client("ssm")
    instance_id = _create_ssm_managed_instance(ctx)

    # Session A: a real data channel under a 1-minute idle timeout, left untouched until it
    # times out on the agent side.
    session_a = _open_idle_session(ctx, ssm, instance_id, _create_session_document(ctx, ssm, 1))
    ctx.on_cleanup(lambda: _safe_terminate(ssm, session_a))

    def _history_probe_a() -> list[dict[str, Any]]:
        resp = ssm.describe_sessions(
            State="History", Filters=[{"key": "SessionId", "value": session_a}]
        )
        return resp.get("Sessions", [])

    history_a = _poll_until(
        _history_probe_a,
        lambda s: len(s) == 1 and s[0].get("Status") == "Terminated",
        timeout_s=240.0,
        interval_s=10.0,
    )
    assert history_a[0]["Status"] == "Terminated", (
        f"expected session {session_a} to be Terminated after its idle timeout, "
        f"got {history_a[0]!r}"
    )

    # Break exactly one thing: try to resume the already-terminated session.
    code, message = _error_code(lambda: ssm.resume_session(SessionId=session_a))
    # Real AWS refuses resuming an idle-terminated session with ValidationException (measured).
    assert code == "ValidationException", (
        f"expected ResumeSession on terminated session {session_a} to fail with "
        f"ValidationException, got code={code!r}"
    )
    assert message == "Session is not in a valid state", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )

    # Effect absent: it must not have been revived by the failed resume attempt.
    history_a_after = _history_probe_a()
    assert len(history_a_after) == 1, (
        f"expected exactly one History entry for {session_a}, got {history_a_after!r}"
    )
    assert history_a_after[0]["Status"] == "Terminated", (
        f"failed resume must not revive the session; expected Terminated, "
        f"got {history_a_after[0]!r}"
    )
    active_after = ssm.describe_sessions(
        State="Active", Filters=[{"key": "SessionId", "value": session_a}]
    )["Sessions"]
    assert active_after == [], (
        f"failed resume must not revive the session; expected no Active entry for "
        f"{session_a}, got {active_after!r}"
    )

    # Positive control: a second session still inside its idle window resumes fine.
    start_b = ssm.start_session(Target=instance_id, DocumentName=_create_session_document(ctx, ssm, 20))
    session_b = start_b["SessionId"]
    ctx.on_cleanup(lambda: _safe_terminate(ssm, session_b))

    def _active_probe_b() -> list[dict[str, Any]]:
        resp = ssm.describe_sessions(
            State="Active", Filters=[{"key": "SessionId", "value": session_b}]
        )
        return resp.get("Sessions", [])

    _poll_until(_active_probe_b, lambda s: len(s) == 1, timeout_s=60.0, interval_s=5.0)
    resume_b = ssm.resume_session(SessionId=session_b)
    assert resume_b["SessionId"] == session_b, (
        f"expected resume of live sibling session {session_b} to return the same "
        f"session id, got {resume_b.get('SessionId')!r}"
    )
    assert resume_b.get("TokenValue"), f"expected a fresh TokenValue, got {resume_b!r}"
    assert resume_b.get("StreamUrl"), f"expected a fresh StreamUrl, got {resume_b!r}"

    # Terminal read, independent of the resume call itself: the second session is still Active,
    # not Terminated, proving the resume succeeded rather than merely echoing the id back.
    still_active_b = _active_probe_b()
    assert len(still_active_b) == 1 and still_active_b[0]["SessionId"] == session_b, (
        f"expected session {session_b} to remain the sole Active entry after resume, "
        f"got {still_active_b!r}"
    )
    assert still_active_b[0].get("Status") != "Terminated", (
        f"expected session {session_b} to still be Active after a successful resume, "
        f"got {still_active_b[0]!r}"
    )


def _safe_terminate(ssm, session_id: str) -> None:
    # A session that already ended answers ValidationException "Session is not in a valid
    # state"; anything else is real.
    try:
        ssm.terminate_session(SessionId=session_id)
    except ClientError as e:
        if "not in a valid state" not in e.response["Error"].get("Message", ""):
            raise


def _error_code(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    try:
        fn()
        return None, None
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]


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


def _require_session_plugin(ctx) -> None:
    # Resolved on the PATH the CLI subprocess runs with, not this process's own.
    path = ctx.subprocess_env().get("PATH")
    if shutil.which("session-manager-plugin", path=path) is None or shutil.which("aws", path=path) is None:
        raise AssertionError(
            "the `aws` CLI and/or the `session-manager-plugin` binary is not installed in this "
            "environment; only a real Session Manager data channel starts the agent-side idle timer"
        )


def _create_session_document(ctx, ssm, idle_minutes: int) -> str:
    """A uniquely named Session document whose literal idleSessionTimeout is *idle_minutes*.

    StartSession never overrides a document's literal idleSessionTimeout input (CreateDocument
    rejects a template there), so the timeout is set per document; the account-wide
    SSM-SessionManagerRunShell is never touched, because other sessions in the account read it.
    """
    name = ctx.unique_name("sim2real-ssm-idle-")
    content = {
        "schemaVersion": "1.0",
        "description": f"Per-check Session Manager preferences ({idle_minutes}-minute idle timeout)",
        "sessionType": "Standard_Stream",
        "inputs": {
            "s3BucketName": "",
            "s3KeyPrefix": "",
            "s3EncryptionEnabled": True,
            "cloudWatchLogGroupName": "",
            "cloudWatchEncryptionEnabled": True,
            "cloudWatchStreamingEnabled": False,
            "kmsKeyId": "",
            "runAsEnabled": False,
            "runAsDefaultUser": "",
            "idleSessionTimeout": str(idle_minutes),
            "maxSessionDuration": "",
            "shellProfile": {"windows": "", "linux": ""},
        },
    }
    ssm.create_document(Name=name, DocumentType="Session", DocumentFormat="JSON", Content=json.dumps(content))
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name))
    return name


def _open_idle_session(ctx, ssm, instance_id: str, document_name: str) -> str:
    """Open a real Session Manager data channel through the CLI and leave it idle; returns the
    session id once it is Connected. The subprocess is stopped at teardown."""
    known = {
        s["SessionId"]
        for state in ("Active", "History")
        for s in ssm.describe_sessions(State=state, Filters=[{"key": "Target", "value": instance_id}])["Sessions"]
    }
    proc = subprocess.Popen(
        ["aws", "ssm", "start-session", "--target", instance_id, "--document-name", document_name,
         "--region", ctx.region],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=ctx.subprocess_env(),
        text=True,
    )

    def _stop() -> None:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)

    ctx.on_cleanup(_stop)
    deadline = time.monotonic() + 90.0
    while True:
        if proc.poll() is not None and proc.returncode != 0:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise AssertionError(
                f"`aws ssm start-session` exited with {proc.returncode} before a session appeared: "
                f"{stderr.strip()[:1000]!r}"
            )
        fresh = [
            s for s in ssm.describe_sessions(State="Active", Filters=[{"key": "Target", "value": instance_id}])["Sessions"]
            if s["SessionId"] not in known and s.get("DocumentName") == document_name
        ]
        if fresh and fresh[0].get("Status") == "Connected":
            return fresh[0]["SessionId"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"no Connected session on {instance_id} for {document_name} within 90s")
        time.sleep(3.0)


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
    # IAM role/instance-profile propagation to EC2 is eventually consistent; poll launch itself.
    while time.monotonic() < deadline and instance_id is None:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                SubnetId=ctx.network().subnet_ids[0],
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
                ],
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
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 200}
        )

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
