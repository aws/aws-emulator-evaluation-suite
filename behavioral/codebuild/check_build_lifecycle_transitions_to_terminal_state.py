"""build-lifecycle-transitions-to-terminal-state."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "build-lifecycle-transitions-to-terminal-state"
GROUP = "state-machine"
SERVICES = ["codebuild"]
_SCENARIO = CHECK

_QUICK_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-ok\n"
_SLEEP_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 180\n"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A build reaches a terminal status on its own, and StopBuild deterministically forces STOPPED."""
    codebuild = ctx.client("codebuild")
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(ctx, role_arn, _QUICK_BUILDSPEC)

    # (1) Natural completion: a quick build reaches a terminal status on its own.
    build_a_id = codebuild.start_build(projectName=project_name)["build"]["id"]
    ctx.on_cleanup(lambda: _try(lambda: codebuild.stop_build(id=build_a_id)))

    def _terminal_a():
        b = codebuild.batch_get_builds(ids=[build_a_id])["builds"][0]
        return b if b["buildStatus"] != "IN_PROGRESS" else None

    build_a = _poll_until(_terminal_a, timeout_s=300, interval_s=5)
    assert build_a is not None, "build never left IN_PROGRESS"
    assert build_a["buildStatus"] == "SUCCEEDED", (
        f"expected natural completion to reach SUCCEEDED, got {build_a['buildStatus']}"
    )

    # (2) Forced stop: a long-running build is deterministically forced to STOPPED.
    codebuild.update_project(name=project_name, source={"type": "NO_SOURCE", "buildspec": _SLEEP_BUILDSPEC})
    build_b_id = codebuild.start_build(projectName=project_name)["build"]["id"]

    def _in_progress_b():
        b = codebuild.batch_get_builds(ids=[build_b_id])["builds"][0]
        return b if b["buildStatus"] == "IN_PROGRESS" else None

    build_b = _poll_until(_in_progress_b, timeout_s=120, interval_s=3)
    assert build_b is not None, "build never reported IN_PROGRESS"

    codebuild.stop_build(id=build_b_id)

    def _stopped_b():
        b = codebuild.batch_get_builds(ids=[build_b_id])["builds"][0]
        return b if b["buildStatus"] != "IN_PROGRESS" else None

    build_b_final = _poll_until(_stopped_b, timeout_s=120, interval_s=3)
    assert build_b_final is not None, "StopBuild never forced a terminal status"
    assert build_b_final["buildStatus"] == "STOPPED", (
        f"expected StopBuild to force STOPPED, got {build_b_final['buildStatus']}"
    )

    ctx.on_cleanup(lambda: _try(lambda: codebuild.batch_delete_builds(ids=[build_a_id, build_b_id])))


# ===== helpers =====
def _try(fn) -> None:
    """Teardown call: an already-absent resource is fine; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
    # No unconditional sleep here: IAM trust-policy propagation has no condition to poll,
    # so the bounded retry-on-InvalidInputException in _create_no_source_project is what
    # actually absorbs it.
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
        tags=[{"key": "sim2real", "value": _SCENARIO}],
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
        assert last_err is not None, "retry loop exited without ever attempting CreateProject"
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
