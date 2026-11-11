"""create-webhook-duplicate-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-webhook-duplicate-name-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWebhook for a project that already has a (manually-created) webhook is
    rejected with ResourceAlreadyExistsException rather than silently replacing the
    existing one; removing it first and re-creating it (positive control) still works."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-wh-")
    _create_github_project(ctx, project_name, role_arn)
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    # manualCreation=True means CodeBuild never calls out to GitHub -- it just
    # allocates a payloadUrl/secret pair -- so no OAuth source credentials are needed.
    first = codebuild.create_webhook(projectName=project_name, manualCreation=True)["webhook"]
    assert first["payloadUrl"], f"expected a payloadUrl on webhook creation, got {first!r}"
    ctx.on_cleanup(lambda: _best_effort_delete_webhook(codebuild, project_name))

    def _create_again() -> dict:
        return codebuild.create_webhook(projectName=project_name, manualCreation=True)["webhook"]

    code, message = _error(_create_again)
    assert (code, message) == (
        "ResourceAlreadyExistsException",
        "Webhook already exists for this project",
    ), (code, message)

    # Effect absent: the original webhook was not replaced by the rejected call.
    project = codebuild.batch_get_projects(names=[project_name])["projects"][0]
    assert project["webhook"]["payloadUrl"] == first["payloadUrl"], (
        f"expected the pre-existing webhook {first['payloadUrl']!r} to survive the rejected "
        f"call, got {project['webhook'].get('payloadUrl')!r}"
    )

    # Positive control: after removing the webhook, creating a new one succeeds.
    codebuild.delete_webhook(projectName=project_name)
    second = codebuild.create_webhook(projectName=project_name, manualCreation=True)["webhook"]
    assert second["payloadUrl"], f"expected a payloadUrl on the re-created webhook, got {second!r}"

    # Terminal read is independent of the mutating create call: the project-level
    # webhook view (a different operation) must now reflect the second webhook, not
    # the deleted first one.
    project_after = codebuild.batch_get_projects(names=[project_name])["projects"][0]
    assert project_after["webhook"]["payloadUrl"] == second["payloadUrl"], (
        f"expected batch_get_projects to reflect the re-created webhook "
        f"{second['payloadUrl']!r}, got {project_after['webhook'].get('payloadUrl')!r}"
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


def _create_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_github_project(ctx, name: str, role_arn: str) -> dict:
    codebuild = ctx.client("codebuild")
    params = {
        "name": name,
        "source": {
            "type": "GITHUB",
            "location": "https://github.com/aws/aws-sdk-go.git",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role_arn,
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    # A freshly-created IAM role is not always immediately assumable (eventual
    # consistency), so CodeBuild can reject it with InvalidInputException for a few
    # seconds after create_role returns; retry with a bounded deadline until it settles.
    last_err = None
    for _ in range(10):
        try:
            return codebuild.create_project(**params)["project"]
        except codebuild.exceptions.InvalidInputException as err:
            last_err = err
            time.sleep(3)
    raise last_err


def _best_effort_delete_webhook(codebuild, project_name: str) -> None:
    try:
        codebuild.delete_webhook(projectName=project_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
