"""create-webhook-duplicate-name-conflict-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-webhook-duplicate-name-conflict-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]

_SCENARIO = "create-webhook-duplicate-name-conflict-rejected"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateWebhook on a project that already has one is rejected with
    ResourceAlreadyExistsException; the original webhook is left untouched, and the
    project can still get a fresh webhook once the existing one is removed."""
    cb = ctx.client("codebuild")
    role_arn = _create_codebuild_service_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-wh-")

    _create_project_with_retry(
        cb,
        name=project_name,
        source={
            "type": "GITHUB",
            # A real, public repo. manualCreation below means CodeBuild never calls out
            # to GitHub to register the hook, so no OAuth/PAT connection is required.
            "location": "https://github.com/aws/aws-codebuild-docker-images.git",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment=_minimal_environment(),
        serviceRole=role_arn,
        logsConfig={"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}},
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    first = cb.create_webhook(projectName=project_name, manualCreation=True)["webhook"]
    ctx.on_cleanup(lambda: _safe_delete_webhook(cb, project_name))
    assert first["payloadUrl"], f"expected a non-empty payloadUrl, got {first!r}"
    assert first["secret"], f"expected a non-empty secret, got {first!r}"

    code, message = _error(lambda: cb.create_webhook(projectName=project_name, manualCreation=True))
    assert (code, message) == (
        "ResourceAlreadyExistsException",
        "Webhook already exists for this project",
    ), (code, message)

    # Effect absent: the project still reports exactly the original webhook, unchanged.
    # (batch_get_projects' Webhook view omits the one-time `secret` field entirely --
    # that's only ever returned inline from CreateWebhook itself -- so compare on the
    # payloadUrl, which IS part of the persisted project-level webhook view.)
    project = cb.batch_get_projects(names=[project_name])["projects"][0]
    assert project["webhook"]["payloadUrl"] == first["payloadUrl"], (
        f"expected the rejected duplicate to leave the original webhook untouched: "
        f"expected payloadUrl {first['payloadUrl']!r}, got {project['webhook']['payloadUrl']!r}"
    )

    # Positive control: once the existing webhook is removed, creating a new one succeeds.
    cb.delete_webhook(projectName=project_name)
    second = cb.create_webhook(projectName=project_name, manualCreation=True)["webhook"]
    assert second["payloadUrl"], f"expected a non-empty payloadUrl, got {second!r}"

    # Terminal read is independent of the CreateWebhook call that just ran: confirm the
    # fresh webhook is visible through the project's persisted view, not just in the
    # mutating call's own response.
    project_after = cb.batch_get_projects(names=[project_name])["projects"][0]
    assert project_after["webhook"]["payloadUrl"] == second["payloadUrl"], (
        f"expected the project's persisted webhook view to reflect the re-created webhook: "
        f"expected payloadUrl {second['payloadUrl']!r}, "
        f"got {project_after['webhook']['payloadUrl']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_webhook(cb, project_name: str) -> None:
    try:
        cb.delete_webhook(projectName=project_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_project_with_retry(cb, timeout_s: float = 40.0, **kwargs):
    """New IAM roles can take a few seconds to be assumable; retry transient rejections."""
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
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
