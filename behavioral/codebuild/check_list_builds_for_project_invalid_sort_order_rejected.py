"""list-builds-for-project-invalid-sort-order-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-builds-for-project-invalid-sort-order-rejected"
GROUP = "ordering"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListBuildsForProject rejects an invalid sortOrder value; the (empty) build list is unaffected and a valid call still succeeds."""
    cb = ctx.client("codebuild")
    role_arn = _create_minimal_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-proj-")
    _create_project_with_retry(
        cb,
        name=project_name,
        source={
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    # Before the invalid call: no build has ever been started for this project.
    before = cb.list_builds_for_project(projectName=project_name)["ids"]
    assert before == [], f"expected no builds before the rejected call, got {before!r}"

    code, message = _client_error(
        lambda: cb.list_builds_for_project(
            projectName=project_name, sortOrder="NOT_A_VALID_ORDER"
        )
    )
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for sortOrder='NOT_A_VALID_ORDER', got {code!r}"
    )
    assert message == "Invalid sort order specified", message

    # Effect absent: the rejected call did not create, alter, or otherwise
    # surface any phantom build entries for the project.
    after = cb.list_builds_for_project(projectName=project_name)["ids"]
    assert after == [], f"expected no builds after the rejected call, got {after!r}"

    # Positive control: a syntactically valid sortOrder against the same
    # project still succeeds (the rejection is specific to the bad value).
    control = cb.list_builds_for_project(projectName=project_name, sortOrder="ASCENDING")["ids"]
    assert control == [], f"expected the positive control to still succeed with [], got {control!r}"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_minimal_codebuild_role(ctx) -> str:
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_project_with_retry(cb, **kwargs) -> None:
    from botocore.exceptions import ClientError

    # IAM role propagation exposes no condition to poll: CodeBuild rejects
    # CreateProject with InvalidInputException on a role it cannot yet assume.
    # Retry that specific error, bounded, until the role is usable.
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cb.create_project(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException":
                last_err = e
                time.sleep(5)
                continue
            raise
    assert last_err is not None, "retry loop exited with no ClientError recorded"
    raise last_err



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
