"""update-project-visibility-invalid-enum-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-project-visibility-invalid-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateProjectVisibility with an out-of-range enum value is rejected with
    InvalidInputException, leaves the project's visibility unchanged, and a
    subsequent call with a valid enum value still succeeds (positive control)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_service_role(ctx)

    project_name = ctx.unique_name("sim2real-behav-cbproj-")
    project = _create_project_with_retry(
        ctx, codebuild, project_name, role_arn
    )
    project_arn = project["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    # Baseline: project is PRIVATE by default.
    baseline = codebuild.batch_get_projects(names=[project_name])["projects"][0]
    assert baseline["projectVisibility"] == "PRIVATE", (
        f"expected new project to default to PRIVATE, got {baseline.get('projectVisibility')!r}"
    )

    # Break exactly one thing: an out-of-range projectVisibility enum value.
    code, message = _client_error(
        lambda: codebuild.update_project_visibility(
            projectArn=project_arn, projectVisibility="TOTALLY_BOGUS_VISIBILITY"
        )
    )
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for an out-of-range projectVisibility, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value 'TOTALLY_BOGUS_VISIBILITY' at 'projectVisibility' failed to satisfy "
        "constraint: Member must satisfy enum value set: [PRIVATE, PUBLIC_READ]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect is absent: visibility unchanged after the rejected call.
    after_reject = codebuild.batch_get_projects(names=[project_name])["projects"][0]
    assert after_reject["projectVisibility"] == "PRIVATE", (
        f"expected visibility to remain PRIVATE after the rejected call, "
        f"got {after_reject.get('projectVisibility')!r}"
    )

    # Positive control: the same operation with a valid enum value succeeds.
    result = codebuild.update_project_visibility(
        projectArn=project_arn, projectVisibility="PRIVATE"
    )
    assert result["projectVisibility"] == "PRIVATE", (
        f"expected a valid projectVisibility update to succeed with PRIVATE, "
        f"got {result.get('projectVisibility')!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_codebuild_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cbrole-")
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
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_project_with_retry(ctx, codebuild, project_name, role_arn, timeout_s=90.0):
    """CreateProject can transiently fail with InvalidInputException while the
    freshly-created IAM role has not yet propagated for codebuild to assume it."""
    from botocore.exceptions import ClientError

    source = {
        "type": "NO_SOURCE",
        "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hello\n",
    }
    artifacts = {"type": "NO_ARTIFACTS"}
    environment = {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
        "computeType": "BUILD_GENERAL1_SMALL",
    }
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(
                name=project_name,
                source=source,
                artifacts=artifacts,
                environment=environment,
                serviceRole=role_arn,
            )["project"]
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidInputException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"CreateProject never succeeded (role propagation): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
