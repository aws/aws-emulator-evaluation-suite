"""codebuild-role-missing-ecr-push-permission-blocks-image-upload."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "codebuild-role-missing-ecr-push-permission-blocks-image-upload"
GROUP = "permission-boundary"
SERVICES = ["codebuild", "codepipeline", "ecr"]

_BUILDSPEC_PUSH = """version: 0.2
phases:
  pre_build:
    commands:
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $REPO_URI
  build:
    commands:
      - printf 'FROM busybox\\nCMD ["echo","hi"]\\n' > Dockerfile
      - docker build -t $REPO_URI:$IMAGE_TAG .
  post_build:
    commands:
      - docker push $REPO_URI:$IMAGE_TAG
"""

_ECR_TOKEN_ONLY_STATEMENT = {
    "Effect": "Allow",
    "Action": ["ecr:GetAuthorizationToken"],
    "Resource": "*",
}

_ECR_PUSH_ALL_STATEMENT = {
    "Effect": "Allow",
    "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
    ],
    "Resource": "*",
}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CodeBuild role with only ecr:GetAuthorizationToken can log in but cannot push; granting
    the SAME role the missing push actions makes the identical build succeed, and a fresh role
    with push permissions from the start succeeds too."""
    ecr = ctx.client("ecr")
    iam = ctx.client("iam")
    repo_name = ctx.unique_name("sim2real-permbnd-")
    repo_uri = _create_ecr_repo(ctx, repo_name)

    # --- negative: role can log in (GetAuthorizationToken) but has none of the push actions ---
    blocked_role_name = ctx.unique_name("sim2real-cbrole-noecr-")
    blocked_role_arn = _create_codebuild_role(ctx, blocked_role_name, _ECR_TOKEN_ONLY_STATEMENT)
    blocked_project = _create_codebuild_project(
        ctx,
        ctx.unique_name("sim2real-cbproj-noecr-"),
        blocked_role_arn,
        _BUILDSPEC_PUSH,
        env_vars={"REPO_URI": repo_uri, "IMAGE_TAG": "blocked"},
    )
    blocked_build = _wait_for_build(ctx, _start_build(ctx, blocked_project))
    assert blocked_build["buildStatus"] == "FAILED", f"expected FAILED, got {blocked_build}"

    code, message = _error(
        lambda: ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "blocked"}])
    )
    assert code == "ImageNotFoundException", (
        f"a build the missing ECR push permission blocked must never have pushed the 'blocked' "
        f"tag; describe_images answered with error code {code!r} instead of "
        f"ImageNotFoundException"
    )
    expected_message = (
        f"The image with imageId {{imageDigest:'null', imageTag:'blocked'}} does not exist "
        f"within the repository with name '{repo_name}' in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- restore: granting the SAME role the missing push actions makes the identical build succeed ---
    _grant_ecr_push(iam, blocked_role_name, _ECR_PUSH_ALL_STATEMENT)
    restored_build = _wait_for_build(
        ctx,
        _start_build(
            ctx, blocked_project, overrides={"REPO_URI": repo_uri, "IMAGE_TAG": "restored"}
        ),
    )
    assert restored_build["buildStatus"] == "SUCCEEDED", (
        f"the identical build must succeed once the role gains ECR push permissions, got "
        f"{restored_build}"
    )
    restored_resp = ecr.describe_images(
        repositoryName=repo_name, imageIds=[{"imageTag": "restored"}]
    )
    assert "restored" in restored_resp["imageDetails"][0]["imageTags"], (
        f"after granting push permissions the 'restored' tag is still missing from "
        f"{restored_resp['imageDetails'][0]['imageTags']!r}"
    )

    # --- positive control: a fresh role with push permissions from the start also succeeds ---
    allowed_role_arn = _create_codebuild_role(
        ctx, ctx.unique_name("sim2real-cbrole-full-"), _ECR_PUSH_ALL_STATEMENT
    )
    allowed_project = _create_codebuild_project(
        ctx,
        ctx.unique_name("sim2real-cbproj-full-"),
        allowed_role_arn,
        _BUILDSPEC_PUSH,
        env_vars={"REPO_URI": repo_uri, "IMAGE_TAG": "allowed"},
    )
    allowed_build = _wait_for_build(ctx, _start_build(ctx, allowed_project))
    assert allowed_build["buildStatus"] == "SUCCEEDED", f"control build failed: {allowed_build}"

    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "allowed"}])
    assert "allowed" in resp["imageDetails"][0]["imageTags"], (
        f"the control build pushed 'allowed' but it is missing from "
        f"{resp['imageDetails'][0]['imageTags']!r}"
    )


def _error(fn):
    """The captured AWS error code and message. An unexpected SUCCESS raises rather than returning a
    falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED with {result!r}")


def _retry_role_propagation(fn, retries: int = 6, delay: float = 10.0):
    """A freshly created/updated CodeBuild service role can take up to roughly a minute for IAM to
    propagate to CodeBuild, which answers InvalidInputException on the role reference until it
    does. Retry the operation itself on that specific error, bounded by `retries`, rather than
    sleeping blind before the first attempt."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidInputException":
                time.sleep(delay)
                continue
            raise
    raise last_err  # type: ignore[misc]


def _create_ecr_repo(ctx: Any, name: str) -> str:
    ecr = ctx.client("ecr")
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    uri = resp["repository"]["repositoryUri"]

    def _cleanup() -> None:
        try:
            ecr.delete_repository(repositoryName=name, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return uri


def _create_codebuild_role(ctx: Any, name: str, ecr_statement: dict) -> str:
    iam = ctx.client("iam")
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
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            ecr_statement,
        ],
    }
    pol_name = f"{name}-policy"
    iam.put_role_policy(RoleName=name, PolicyName=pol_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pol_name))
    return role_arn


def _grant_ecr_push(iam: Any, role_name: str, ecr_statement: dict) -> None:
    """Replace the named role's policy with one that includes the given ECR statement, reusing
    the same PolicyName `_create_codebuild_role` established -- this is an update, not a new
    grant, so the existing cleanup already covers it."""
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            ecr_statement,
        ],
    }
    pol_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=pol_name, PolicyDocument=json.dumps(policy_doc)
    )


def _create_codebuild_project(
    ctx: Any,
    name: str,
    role_arn: str,
    buildspec: str,
    env_vars: dict[str, str] | None = None,
    privileged: bool = True,
) -> str:
    cb = ctx.client("codebuild")
    env_list = [{"name": k, "value": v, "type": "PLAINTEXT"} for k, v in (env_vars or {}).items()]
    _retry_role_propagation(
        lambda: cb.create_project(
            name=name,
            source={"type": "NO_SOURCE", "buildspec": buildspec},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "privilegedMode": privileged,
                "environmentVariables": env_list,
            },
            serviceRole=role_arn,
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=name))
    return name


def _start_build(
    ctx: Any,
    project_name: str,
    overrides: dict[str, str] | None = None,
    buildspec_override: str | None = None,
) -> str:
    cb = ctx.client("codebuild")
    kwargs: dict[str, Any] = {"projectName": project_name}
    if overrides:
        kwargs["environmentVariablesOverride"] = [
            {"name": k, "value": v, "type": "PLAINTEXT"} for k, v in overrides.items()
        ]
    if buildspec_override:
        kwargs["buildspecOverride"] = buildspec_override
    return _retry_role_propagation(lambda: cb.start_build(**kwargs)["build"]["id"])


def _wait_for_build(ctx: Any, build_id: str, timeout_s: float = 900.0, interval_s: float = 15.0):
    cb = ctx.client("codebuild")
    deadline = time.monotonic() + timeout_s
    build = None
    while time.monotonic() < deadline:
        build = cb.batch_get_builds(ids=[build_id])["builds"][0]
        if build["buildStatus"] != "IN_PROGRESS":
            return build
        time.sleep(interval_s)
    raise AssertionError(f"build {build_id} did not complete within {timeout_s}s: {build}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
