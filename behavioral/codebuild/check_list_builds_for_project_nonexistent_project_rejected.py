"""list-builds-for-project-nonexistent-project-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-builds-for-project-nonexistent-project-rejected"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListBuildsForProject on a nonexistent project must raise ResourceNotFoundException."""
    codebuild = ctx.client("codebuild")
    bogus_name = ctx.unique_name("sim2real-cb-nope-")

    code, message = _client_error(lambda: codebuild.list_builds_for_project(projectName=bogus_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent project, got {code!r}"
    )
    assert message == f"The provided project arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{bogus_name} does not exist.", message

    # Positive control: the same call against a real, existing project must succeed.
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(ctx, role_arn, _QUICK_BUILDSPEC)
    response = codebuild.list_builds_for_project(projectName=project_name)
    assert response.get("ids", []) == [], (
        f"expected no builds for a fresh project, got {response.get('ids')}"
    )


# ===== helpers =====
_QUICK_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-ok\n"


def _try(fn) -> None:
    """Teardown call: an already-absent resource is fine; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _make_codebuild_role(ctx) -> str:
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        _try(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
        _try(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "s3:*",
                    "codebuild:*",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    # No unconditional sleep: IAM role propagation is bounded by the
    # InvalidInputException retry loop in _create_no_source_project below.
    return role_arn


def _create_no_source_project(
    ctx, role_arn: str, buildspec: str, extra: dict[str, Any] | None = None
) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    kwargs: dict[str, Any] = dict(
        name=name,
        source={"type": "NO_SOURCE", "buildspec": buildspec},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    if extra:
        kwargs.update(extra)

    from botocore.exceptions import ClientError

    # A freshly created IAM role's trust policy can take several seconds to become
    # visible to CodeBuild (documented IAM eventual-consistency behavior), so bound
    # the retry on that specific error rather than sleeping unconditionally.
    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException":
                last_err = e
                time.sleep(5)
                continue
            raise
    else:
        assert last_err is not None, "retry loop exited without ever raising InvalidInputException"
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
