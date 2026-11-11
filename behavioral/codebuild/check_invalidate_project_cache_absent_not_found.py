"""invalidate-project-cache-absent-not-found."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return the botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED: {result!r}")

CHECK = "invalidate-project-cache-absent-not-found"
GROUP = 'error-semantics'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """InvalidateProjectCache on a project name that has never existed raises
    ResourceNotFoundException, while the identical call against a real project succeeds
    (positive control) -- so the rejection is specific to absence, not to every call."""
    cb = ctx.client("codebuild")
    missing_name = ctx.unique_name("sim2real-behav-missing-proj-")
    code, message = _client_error(lambda: cb.invalidate_project_cache(projectName=missing_name))
    assert code == "ResourceNotFoundException", code
    assert message == f"Project does not exist: {missing_name}.", message

    real_name = _create_minimal_project(ctx)
    cb.invalidate_project_cache(projectName=real_name)


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_minimal_project(ctx) -> str:
    """Create a NO_SOURCE/NO_ARTIFACTS CodeBuild project that never runs a build, just
    enough to exercise project-scoped control-plane calls."""
    cb = ctx.client("codebuild")
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
    # A brand-new IAM role's trust policy can take a few seconds to become visible to
    # other AWS services (documented IAM eventual-consistency behavior), so poll
    # CreateProject rather than asserting immediately.
    deadline = time.monotonic() + 45.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = cb.create_project(
                name=name,
                source=source,
                artifacts=artifacts,
                environment=environment,
                serviceRole=role_arn,
            )
            ctx.on_cleanup(lambda n=name: cb.delete_project(name=n))
            return resp["project"]["name"]
        except cb.exceptions.InvalidInputException as err:
            last_err = err
            time.sleep(3.0)
    raise AssertionError(f"CreateProject never succeeded (IAM role propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
