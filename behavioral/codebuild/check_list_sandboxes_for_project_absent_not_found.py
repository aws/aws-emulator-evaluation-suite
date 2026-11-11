"""list-sandboxes-for-project-absent-not-found."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-sandboxes-for-project-absent-not-found"
GROUP = "error-semantics"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSandboxesForProject against a nonexistent project raises
    ResourceNotFoundException, while the identical call against a real project
    (which has never had a sandbox started) succeeds and returns an empty id list."""
    codebuild = ctx.client("codebuild")
    missing_name = ctx.unique_name("sim2real-nonexistent-proj-")

    code, code_msg = _client_error(lambda: codebuild.list_sandboxes_for_project(projectName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert code_msg == f"The provided project arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{missing_name} does not exist.", f"unexpected message: {code_msg!r}"

    real_name = _create_minimal_project(ctx)
    resp = codebuild.list_sandboxes_for_project(projectName=real_name)
    assert resp.get("ids", []) == [], f"expected no sandboxes for a fresh project, got {resp.get('ids')}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    """Create a NO_SOURCE/NO_ARTIFACTS CodeBuild project that never starts a sandbox,
    just enough to exercise project-scoped read APIs."""
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
