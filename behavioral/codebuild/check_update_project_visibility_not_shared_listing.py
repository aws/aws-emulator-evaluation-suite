"""update-project-visibility-not-shared-listing."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-project-visibility-not-shared-listing"
GROUP = "server-side"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A project made PUBLIC_READ keeps that visibility yet stays out of ListSharedProjects.
    Public and shared differ: ListSharedProjects lists only projects shared with the caller.

    Reference: https://docs.aws.amazon.com/codebuild/latest/userguide/project-sharing.html
    """
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_service_role(ctx)
    name = ctx.unique_name("sim2real-cbvis-")
    project = _create_project_with_retry(ctx, codebuild, name, role_arn)

    resp = codebuild.update_project_visibility(
        projectArn=project["arn"], projectVisibility="PUBLIC_READ"
    )
    assert resp["projectVisibility"] == "PUBLIC_READ", (
        f"expected UpdateProjectVisibility to echo PUBLIC_READ, got {resp['projectVisibility']!r}"
    )
    assert resp.get("publicProjectAlias"), (
        f"expected a publicProjectAlias once PUBLIC_READ, got {resp.get('publicProjectAlias')!r}"
    )

    # The change must be durable, not just echoed back on the same call.
    described = codebuild.batch_get_projects(names=[name])["projects"][0]
    assert described["projectVisibility"] == "PUBLIC_READ", (
        f"expected BatchGetProjects to persist PUBLIC_READ, got {described['projectVisibility']!r}"
    )

    shared_arns = _collect_all(codebuild.list_shared_projects, "projects")
    assert project["arn"] not in shared_arns, (
        f"expected {project['arn']!r} absent from ListSharedProjects (public != shared), "
        f"found it in {shared_arns!r}"
    )

    back = codebuild.update_project_visibility(
        projectArn=project["arn"], projectVisibility="PRIVATE"
    )
    assert back["projectVisibility"] == "PRIVATE", (
        f"expected UpdateProjectVisibility to echo PRIVATE, got {back['projectVisibility']!r}"
    )
    described_again = codebuild.batch_get_projects(names=[name])["projects"][0]
    assert described_again["projectVisibility"] == "PRIVATE", (
        f"expected BatchGetProjects to persist the revert to PRIVATE, "
        f"got {described_again['projectVisibility']!r}"
    )


def _create_codebuild_service_role(ctx: Any) -> str:
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="codebuild-logs", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="codebuild-logs"))
    return role["Arn"]


def _create_project_with_retry(ctx: Any, codebuild: Any, name: str, role_arn: str) -> dict:
    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = codebuild.create_project(
                name=name,
                source={
                    "type": "NO_SOURCE",
                    "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
                },
                artifacts={"type": "NO_ARTIFACTS"},
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": "aws/codebuild/standard:7.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                },
                serviceRole=role_arn,
                tags=[{"key": "sim2real", "value": "true"}],
            )
            project = resp["project"]
            ctx.on_cleanup(lambda: codebuild.delete_project(name=name))
            return project
        except ClientError as e:
            # IAM role trust/propagation can lag right after CreateRole.
            if e.response["Error"]["Code"] == "InvalidInputException":
                last_err = e
                time.sleep(3)
                continue
            raise
    assert last_err is not None
    raise last_err


def _collect_all(list_fn: Any, key: str) -> list[str]:
    items: list[str] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = list_fn(**kwargs)
        items.extend(resp.get(key, []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
