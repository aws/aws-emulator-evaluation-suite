"""update-project-visibility-invalid-value-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-project-visibility-invalid-value-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProjectVisibility with a value outside PUBLIC_READ/PRIVATE is rejected and
    the project's visibility is left untouched."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_service_role(ctx)

    project_name = ctx.unique_name("sim2real-cb-proj-")
    _create_project_with_retry(codebuild, ctx, project_name, role_arn)
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))
    project_arn = codebuild.batch_get_projects(names=[project_name])["projects"][0]["arn"]

    code, message = _client_error(
        lambda: codebuild.update_project_visibility(
            projectArn=project_arn, projectVisibility="SUPER_PUBLIC"
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    expected = (
        "1 validation error detected: Value 'SUPER_PUBLIC' at 'projectVisibility' failed to satisfy "
        "constraint: Member must satisfy enum value set: [PRIVATE, PUBLIC_READ]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: visibility remains the default PRIVATE
    project = codebuild.batch_get_projects(names=[project_name])["projects"][0]
    assert project.get("projectVisibility", "PRIVATE") == "PRIVATE"

    # positive control: a value within the allowed enum is accepted
    ok_resp = codebuild.update_project_visibility(
        projectArn=project_arn, projectVisibility="PRIVATE"
    )
    assert ok_resp["projectVisibility"] == "PRIVATE"
    project_after = codebuild.batch_get_projects(names=[project_name])["projects"][0]
    assert project_after.get("projectVisibility", "PRIVATE") == "PRIVATE"


def _create_project_with_retry(codebuild, ctx, project_name: str, role_arn: str) -> None:
    """CreateProject, retrying through IAM trust-policy propagation before it succeeds."""
    deadline = time.monotonic() + 90
    while True:
        try:
            codebuild.create_project(**_basic_project_params(role_arn, project_name))
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_service_role(ctx) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
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
        RoleName=role_name,
        PolicyName="sim2real-cb-inline",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-inline")
    )
    return role_arn


def _basic_project_params(role_arn: str, name: str) -> dict[str, Any]:
    return {
        "name": name,
        "source": {
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
