"""sandbox-idle-timeout-auto-stop."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sandbox-idle-timeout-auto-stop"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codebuild"]

# Marks a resource that was accepted but never converged, so it reads as a failure, not an
# environment error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


_QUICK_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-ok\n"

# Sandbox timeoutInMinutes ranges 5-2160 (API_Sandbox); 5 is the documented minimum.
_SANDBOX_TIMEOUT_MINUTES = 5

# The 5-minute idle timeout plus scheduling margin.
_IDLE_TIMEOUT_S = 600.0


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Sandbox.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A sandbox left untouched past its configured timeoutInMinutes auto-transitions to STOPPED;
    unlike a Build (TIMED_OUT), the idle auto-stop reports the same status as StopSandbox.

    Reference: https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Sandbox.html
    """

    codebuild = ctx.client("codebuild")
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(
        ctx, role_arn, _QUICK_BUILDSPEC, extra={"timeoutInMinutes": _SANDBOX_TIMEOUT_MINUTES}
    )

    sandbox = codebuild.start_sandbox(projectName=project_name)["sandbox"]
    sandbox_id = sandbox["id"]
    ctx.on_cleanup(lambda: _stop_sandbox(codebuild, sandbox_id))
    # The sandbox instance must actually carry the project's configured timeout, not a default.
    assert sandbox.get("timeoutInMinutes") == _SANDBOX_TIMEOUT_MINUTES, (
        f"expected timeoutInMinutes={_SANDBOX_TIMEOUT_MINUTES} on StartSandbox's own response, "
        f"got {sandbox.get('timeoutInMinutes')!r}"
    )

    def _running():
        s = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
        return s if s["status"] == "RUNNING" else None

    running = _poll_until(_running, timeout_s=180, interval_s=5)
    if running is None:
        raise _never_ready(
            "sandbox never reached RUNNING within the bounded provisioning window",
        )
    assert running.get("timeoutInMinutes") == _SANDBOX_TIMEOUT_MINUTES, (
        f"expected timeoutInMinutes={_SANDBOX_TIMEOUT_MINUTES} once RUNNING, "
        f"got {running.get('timeoutInMinutes')!r}"
    )

    # Untouched from here: no command execution, no StopSandbox. The service's own idle
    # timer, not this check, must move the sandbox off RUNNING.
    def _off_running():
        s = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
        return s if s["status"] != "RUNNING" else None

    terminal = _poll_until(_off_running, timeout_s=_IDLE_TIMEOUT_S, interval_s=15)
    if terminal is None:
        raise _never_ready(
            f"sandbox stayed RUNNING past its {_SANDBOX_TIMEOUT_MINUTES}-minute configured "
            f"idle timeout (waited {_IDLE_TIMEOUT_S:.0f}s untouched)"
        )
    assert terminal["status"] == "STOPPED", (
        f"expected the idle sandbox to auto-transition to STOPPED, got {terminal['status']!r}"
    )


def _try(fn) -> None:
    """Teardown call: an already-absent resource is fine; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _stop_sandbox(codebuild, sandbox_id: str) -> None:
    """Teardown: stops the sandbox unless already stopped, retrying while it is still starting."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    while True:
        sandboxes = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"]
        if not sandboxes:
            return  # an absent id is already gone
        status = sandboxes[0]["status"]
        if status in ("STOPPING", "STOPPED", "FAILED"):
            return
        try:
            codebuild.stop_sandbox(id=sandbox_id)
            return
        except ClientError as exc:
            # StopSandbox refuses a sandbox that is still starting up.
            if exc.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = probe()
        if value is not None:
            return value
        time.sleep(interval_s)
    return None


def _make_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        _try(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
        _try(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "s3:*",
                    "ssmmessages:*",
                    "ssm:StartSession",
                    "codebuild:*",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    # IAM propagation is absorbed by _create_no_source_project's bounded retry.
    return role_arn


def _create_no_source_project(
    ctx, role_arn: str, buildspec: str, extra: dict[str, Any] | None = None
) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    kwargs: dict[str, Any] = dict(
        name=name,
        source={"type": "NO_SOURCE", "buildspec": buildspec},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    if extra:
        kwargs.update(extra)

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException":
                last_err = e
                time.sleep(5)
                continue
            raise
    else:
        assert last_err is not None, "loop exhausted its deadline with no ClientError recorded"
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
