"""stop-build-transitions-to-stopped-state."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-build-transitions-to-stopped-state"
GROUP = "state-machine"
SERVICES = ["codebuild"]

# The build sleeps far longer than this check runs, so the check holds the build in
# progress until its own StopBuild.
_HOLDING_BUILDSPEC = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - sleep 600\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopBuild on an in-progress build causes BatchGetBuilds to report a terminal STOPPED
    buildStatus with finalized phases (endTime set, a phase reflecting the stop)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-proj-")

    _create_project_with_retry(
        ctx,
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": _HOLDING_BUILDSPEC},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    start_resp = codebuild.start_build(projectName=project_name)
    build = start_resp["build"]
    build_id = build["id"]
    assert build["buildStatus"] == "IN_PROGRESS", f"unexpected start status: {build}"

    def _cleanup_build() -> None:
        try:
            codebuild.stop_build(id=build_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        codebuild.batch_delete_builds(ids=[build_id])

    ctx.on_cleanup(_cleanup_build)

    def _probe() -> dict[str, Any]:
        resp = codebuild.batch_get_builds(ids=[build_id])
        found = resp["builds"]
        assert len(found) == 1, f"build {build_id} not found via BatchGetBuilds: {resp}"
        return found[0]

    in_progress = _poll_until(
        _probe, lambda b: b["buildStatus"] == "IN_PROGRESS", timeout_s=60.0, interval_s=3.0
    )
    assert in_progress["buildStatus"] == "IN_PROGRESS", (
        f"expected IN_PROGRESS before stopping, got: {in_progress}"
    )

    codebuild.stop_build(id=build_id)

    stopped = _poll_until(
        _probe, lambda b: b["buildStatus"] == "STOPPED", timeout_s=120.0, interval_s=5.0
    )
    assert stopped["buildStatus"] == "STOPPED", f"expected STOPPED after StopBuild, got: {stopped}"
    assert stopped.get("endTime") is not None, "STOPPED build must have a finalized endTime"
    phases = stopped.get("phases") or []
    assert phases, "STOPPED build must report finalized phases"
    assert any(p.get("phaseStatus") == "STOPPED" for p in phases), (
        f"expected a phase reflecting the stop, got: {phases}"
    )


# ===== helpers =====

def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-cb-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "s3:*",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_project_with_retry(ctx, *, timeout_s: float = 90.0, **kwargs) -> dict[str, Any]:
    """CreateProject can transiently fail with InvalidInputException while the freshly
    created IAM service role has not yet propagated; retry within a bounded window."""
    codebuild = ctx.client("codebuild")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidInputException" and "role" in message.lower():
                last_exc = exc
                time.sleep(5)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling create_project"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
