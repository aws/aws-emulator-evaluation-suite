"""e2e-retry-build-creates-linked-build."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-retry-build-creates-linked-build"
GROUP = "e2e"
SERVICES = ["codebuild"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    }
)

_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 90\n"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RetryBuild on a stopped build creates a new build in the same project whose
    build-number sequence and source metadata link it to the original build."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-behav-retryproj-")
    _create_project_with_role_propagation_retry(
        ctx,
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": _BUILDSPEC},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    original_id = _start_build_with_retry(ctx, project_name)

    def _get(build_id: str) -> dict:
        return codebuild.batch_get_builds(ids=[build_id])["builds"][0]

    in_progress = _poll_until(
        lambda: _get(original_id), lambda b: b["currentPhase"] != "SUBMITTED" or b["buildComplete"],
        timeout_s=180, interval_s=5,
    )
    assert in_progress["buildStatus"] == "IN_PROGRESS", in_progress

    codebuild.stop_build(id=original_id)
    original = _poll_until(lambda: _get(original_id), lambda b: b["buildComplete"], timeout_s=180, interval_s=5)
    assert original["buildStatus"] == "STOPPED", original

    retried = codebuild.retry_build(id=original_id)["build"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, retried["id"]))

    assert retried["id"] != original_id, "retry must create a NEW build id, not reuse the original"
    assert retried["projectName"] == original["projectName"], (
        f"expected retried projectName {original['projectName']!r}, got {retried['projectName']!r}"
    )
    assert retried["buildNumber"] == original["buildNumber"] + 1, (
        f"expected retried build-number {original['buildNumber'] + 1}, got {retried['buildNumber']}"
    )
    assert retried["source"]["type"] == original["source"]["type"], (
        f"expected retried source type {original['source']['type']!r}, got {retried['source']['type']!r}"
    )

    # Drive the retried build to a terminal state too, proving it is a real, independently
    # running build (not a static echo of the request) before cleanup deletes the project.
    retried_progressed = _poll_until(
        lambda: _get(retried["id"]),
        lambda b: b["currentPhase"] != "SUBMITTED" or b["buildComplete"],
        timeout_s=180,
        interval_s=5,
    )
    assert retried_progressed["buildStatus"] == "IN_PROGRESS", retried_progressed
    codebuild.stop_build(id=retried["id"])
    retried_final = _poll_until(lambda: _get(retried["id"]), lambda b: b["buildComplete"], timeout_s=180, interval_s=5)
    assert retried_final["buildStatus"] == "STOPPED", (
        f"expected retried build to reach STOPPED, got {retried_final['buildStatus']}"
    )


def _create_codebuild_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cb-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline-logs", PolicyDocument=_ROLE_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-logs"))
    return role["Arn"]


def _create_project_with_role_propagation_retry(
    ctx: Any, *, timeout_s: float = 90.0, interval_s: float = 3.0, **params: Any
) -> None:
    """CreateProject can reject a just-minted role with InvalidInputException until IAM's
    trust-policy write propagates; retry on exactly that signal, never on a bare sleep."""
    codebuild = ctx.client("codebuild")
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**params)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidInputException" and (
                "not authorized" in message or "assume" in message.lower()
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"create_project never succeeded within {timeout_s}s: {last_err}")


def _start_build_with_retry(ctx: Any, project_name: str, attempts: int = 6) -> str:
    codebuild = ctx.client("codebuild")
    last_err = None
    for _ in range(attempts):
        try:
            return codebuild.start_build(projectName=project_name)["build"]["id"]
        except ClientError as err:
            last_err = err
            time.sleep(5)
    raise AssertionError(f"start_build never succeeded after retries: {last_err}")


def _best_effort_stop(ctx: Any, build_id: str) -> None:
    codebuild = ctx.client("codebuild")
    try:
        codebuild.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
