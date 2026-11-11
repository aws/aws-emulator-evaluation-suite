"""stop-build-nonexistent-id-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-build-nonexistent-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopBuild against a well-formed but nonexistent build id is rejected with
    ResourceNotFoundException, leaves the real (still running) build untouched, and
    a same-file positive control confirms StopBuild against the real id works."""
    iam = ctx.client("iam")
    cb = ctx.client("codebuild")

    role_arn = _create_codebuild_role(ctx, iam)
    project_name = ctx.unique_name("sim2real-cb-proj-")
    _create_project(ctx, cb, project_name, role_arn)

    build = cb.start_build(projectName=project_name)["build"]
    real_id = build["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(cb, real_id))
    assert build["buildStatus"] == "IN_PROGRESS", f"expected IN_PROGRESS, got {build['buildStatus']!r}"

    # A syntactically valid id ("<project>:<uuid>") that was never created.
    bogus_id = f"{project_name}:00000000-0000-0000-0000-000000000000"

    code, message = _error(lambda: cb.stop_build(id=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Build {bogus_id} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the real build must be untouched by the rejected call. The buildspec
    # sleeps far longer than this check runs, so the build is held IN_PROGRESS here.
    still_running = cb.batch_get_builds(ids=[real_id])["builds"][0]["buildStatus"]
    assert still_running == "IN_PROGRESS", f"real build status changed to {still_running!r}"

    # Positive control: stopping the real id succeeds and transitions to STOPPED.
    cb.stop_build(id=real_id)
    final_status = _poll_until(
        lambda: cb.batch_get_builds(ids=[real_id])["builds"][0]["buildStatus"],
        lambda status: status != "IN_PROGRESS",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final_status == "STOPPED", f"expected STOPPED, got {final_status!r}"


def _create_codebuild_role(ctx, iam) -> str:
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "logs"
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
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_project(ctx, cb, name: str, role_arn: str) -> None:
    ctx.on_cleanup(lambda: cb.delete_project(name=name))
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 600\n"
    last_err: Exception | None = None
    for _ in range(10):
        try:
            cb.create_project(
                name=name,
                source={"type": "NO_SOURCE", "buildspec": buildspec},
                artifacts={"type": "NO_ARTIFACTS"},
                environment={
                    "type": "LINUX_CONTAINER",
                    "computeType": "BUILD_GENERAL1_SMALL",
                    "image": "aws/codebuild/standard:7.0",
                },
                serviceRole=role_arn,
                tags=[{"key": "sim2real", "value": "stop-build-nonexistent-id-rejected"}],
            )
            return
        except Exception as exc:  # noqa: BLE001 - retry on IAM propagation delay
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"could not create project (role propagation?): {last_err}")


def _best_effort_stop(cb, build_id: str) -> None:
    try:
        cb.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
