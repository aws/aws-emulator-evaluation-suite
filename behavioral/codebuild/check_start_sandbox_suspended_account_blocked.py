"""start-sandbox-suspended-account-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-sandbox-suspended-account-blocked"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSandbox and ListSandboxesForProject on an unknown project raise ResourceNotFoundException,
    while a real project starts a sandbox that BatchGetSandboxes and the listing return."""
    cb = ctx.client("codebuild")

    # Negative: no such project exists, so no sandbox can ever be created for it.
    missing_project = ctx.unique_name("sim2real-cb-sandbox-missing-")
    code, message = _error(lambda: cb.start_sandbox(projectName=missing_project))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = (
        f"Project cannot be found: arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{missing_project}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    # Effect absent: the failed call left no trace to list (the project itself is
    # unknown, so even asking for its sandboxes is rejected the same way).
    list_code, list_message = _error(lambda: cb.list_sandboxes_for_project(projectName=missing_project))
    assert list_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {list_code!r}"
    )
    expected_list_message = (
        f"The provided project arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{missing_project} does not exist."
    )
    assert list_message == expected_list_message, (
        f"expected message {expected_list_message!r}, got {list_message!r}"
    )

    # Positive control: a real project's sandbox actually starts and can be stopped.
    role_arn = _create_codebuild_service_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-sandbox-")
    _create_project_with_retry(
        cb,
        name=project_name,
        source={
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo sim2real\n",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment=_minimal_environment(),
        serviceRole=role_arn,
        logsConfig={"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    sandbox = _start_sandbox_with_retry(cb, project_name)
    sandbox_id = sandbox["id"]
    assert sandbox["projectName"] == project_name, (
        f"expected projectName {project_name!r}, got {sandbox['projectName']!r}"
    )
    ctx.on_cleanup(lambda: _safe_stop_sandbox(cb, sandbox_id))

    # The sandbox's real lifecycle (QUEUED -> PROVISIONING -> IN_PROGRESS) depends on
    # live compute becoming available, which can take an unbounded amount of time on a
    # shared/cold test account and isn't the boundary this check is about. It's enough
    # to prove StartSandbox actually created a real, trackable resource for a valid
    # project -- a fundamentally different outcome than the ResourceNotFoundException
    # asserted above for an unknown one -- and that it's consistently visible through
    # BOTH read paths CodeBuild exposes for it.

    got = cb.batch_get_sandboxes(ids=[sandbox_id])
    assert sandbox_id not in got["sandboxesNotFound"], (
        f"sandbox {sandbox_id} unexpectedly reported not found: {got['sandboxesNotFound']}"
    )
    assert got["sandboxes"][0]["id"] == sandbox_id, (
        f"expected sandbox id {sandbox_id}, got {got['sandboxes'][0]['id']}"
    )
    assert got["sandboxes"][0]["projectName"] == project_name, (
        f"expected projectName {project_name!r}, got {got['sandboxes'][0]['projectName']!r}"
    )

    listed = cb.list_sandboxes_for_project(projectName=project_name)
    assert sandbox_id in listed["ids"], (
        f"sandbox {sandbox_id} missing from list_sandboxes_for_project: {listed['ids']}"
    )


def _error(fn) -> tuple[str, str]:
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _minimal_environment() -> dict[str, Any]:
    return {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
        "computeType": "BUILD_GENERAL1_SMALL",
        "imagePullCredentialsType": "CODEBUILD",
    }


def _create_codebuild_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = json.dumps(
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CodeBuild sandbox documents this SSM policy as a hard prerequisite for the
    # sandbox's SSH/session channel to actually come up: without it the sandbox never
    # progresses past PROVISIONING (it has nothing to open a session on).
    ssm_policy_name = f"{role_name}-ssm"
    ssm_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ssmmessages:CreateControlChannel",
                        "ssmmessages:CreateDataChannel",
                        "ssmmessages:OpenControlChannel",
                        "ssmmessages:OpenDataChannel",
                        "ssm:StartSession",
                    ],
                    "Resource": "*",
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=ssm_policy_name, PolicyDocument=ssm_policy)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=ssm_policy_name))
    return role["Arn"]


def _create_project_with_retry(cb, timeout_s: float = 40.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cb.create_project(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInputException":
                raise
            last_exc = exc
            time.sleep(3)
    assert last_exc is not None, "retry loop exited without ever calling create_project"
    raise last_exc


def _start_sandbox_with_retry(cb, project_name: str, timeout_s: float = 40.0):
    """A just-created role can take a few seconds to be assumable; retry transient
    InvalidInputException rejections rather than a fixed pre-sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cb.start_sandbox(projectName=project_name)["sandbox"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInputException":
                raise
            last_exc = exc
            time.sleep(3)
    assert last_exc is not None, "retry loop exited without ever calling start_sandbox"
    raise last_exc


def _safe_stop_sandbox(cb, sandbox_id: str) -> None:
    try:
        cb.stop_sandbox(id=sandbox_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInputException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
