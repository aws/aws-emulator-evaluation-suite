"""delete-webhook-absent-project-not-found."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "delete-webhook-absent-project-not-found"
GROUP = "error-semantics"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWebhook on a project that never existed raises ResourceNotFoundException "Project does not
    exist", while on a real project without a webhook it succeeds and the project stays webhook-free."""
    codebuild = ctx.client("codebuild")
    missing_project_name = ctx.unique_name("sim2real-behav-nonexistent-proj-")

    code, message = _client_error(
        lambda: codebuild.delete_webhook(projectName=missing_project_name)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Project does not exist", message

    # Positive control / discriminator: a real project with no webhook configured
    # is left completely intact, and DeleteWebhook against it succeeds as a
    # no-op (NOT a ResourceNotFoundException) -- proving the error
    # above is keyed on the missing *project*, not a generically-absent webhook.
    project_name = _create_minimal_project(ctx)
    got = codebuild.batch_get_projects(names=[project_name])
    assert got["projectsNotFound"] == []
    assert len(got["projects"]) == 1
    assert got["projects"][0]["name"] == project_name
    assert "webhook" not in got["projects"][0]

    # A rejection here raises ClientError and fails the check.
    codebuild.delete_webhook(projectName=project_name)

    # The project itself remains completely unaffected by the no-op delete.
    got_after = codebuild.batch_get_projects(names=[project_name])
    assert got_after["projectsNotFound"] == []
    assert got_after["projects"][0]["name"] == project_name


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_codebuild_service_role(ctx) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_minimal_project(ctx) -> str:
    """Create a NO_SOURCE/NO_ARTIFACTS CodeBuild project (webhooks unsupported for
    this source type, and none is ever created)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_service_role(ctx)
    name = ctx.unique_name("sim2real-behav-proj-")
    source = {
        "type": "NO_SOURCE",
        "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
    }
    artifacts: dict[str, Any] = {"type": "NO_ARTIFACTS"}
    environment = {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
        "computeType": "BUILD_GENERAL1_SMALL",
    }
    # A brand-new IAM role's trust policy can take a few seconds to become visible
    # to other AWS services (documented IAM eventual-consistency behavior), so poll
    # CreateProject rather than asserting immediately.
    deadline = time.monotonic() + 45.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = codebuild.create_project(
                name=name,
                source=source,
                artifacts=artifacts,
                environment=environment,
                serviceRole=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            ctx.on_cleanup(lambda n=name: codebuild.delete_project(name=n))
            return resp["project"]["name"]
        except codebuild.exceptions.InvalidInputException as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"CreateProject never succeeded (IAM role propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
