"""codebuild-pulls-base-image-from-ecr-private-registry."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "codebuild-pulls-base-image-from-ecr-private-registry"
GROUP = "image-delivery"
SERVICES = ["codebuild", "codepipeline", "ecr"]

_BUILDSPEC_PUSH_BASE = """version: 0.2
phases:
  pre_build:
    commands:
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $REPO_URI
  build:
    commands:
      - printf 'FROM busybox\\nCMD ["echo","hi"]\\n' > Dockerfile
      - docker build -t $REPO_URI:base .
  post_build:
    commands:
      - docker push $REPO_URI:base
"""

_BUILDSPEC_PULL_BASE_AND_BUILD = """version: 0.2
phases:
  pre_build:
    commands:
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $BASE_URI
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $FINAL_URI
  build:
    commands:
      - docker pull $BASE_URI:base
      - printf 'FROM %s:base\\nRUN echo built-on-private-base > /marker.txt\\n' "$BASE_URI" > Dockerfile
      - docker build -t $FINAL_URI:derived .
  post_build:
    commands:
      - docker push $FINAL_URI:derived
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CodeBuild pulls a private ECR base image (via its service role) and builds FROM it."""
    ecr = ctx.client("ecr")
    base_repo_name = ctx.unique_name("sim2real-basrepo-")
    final_repo_name = ctx.unique_name("sim2real-finrepo-")
    base_uri = _create_ecr_repo(ctx, base_repo_name)
    final_uri = _create_ecr_repo(ctx, final_repo_name)

    role_arn = _create_codebuild_role(
        ctx, ctx.unique_name("sim2real-cbrole-"), _ECR_PUSH_ALL_STATEMENT
    )
    project = _create_codebuild_project(
        ctx,
        ctx.unique_name("sim2real-cbproj-"),
        role_arn,
        _BUILDSPEC_PUSH_BASE,
        env_vars={"REPO_URI": base_uri},
    )

    # Step 1: push a base image into the private ECR repo.
    setup_build_id = _start_build(ctx, project)
    setup_build = _wait_for_build(ctx, setup_build_id)
    assert setup_build["buildStatus"] == "SUCCEEDED", f"base push failed: {setup_build}"

    # Step 2: a second build FROMs that private base image and pushes a derived image.
    pull_build_id = _start_build(
        ctx,
        project,
        overrides={"BASE_URI": base_uri, "FINAL_URI": final_uri},
        buildspec_override=_BUILDSPEC_PULL_BASE_AND_BUILD,
    )
    pull_build = _wait_for_build(ctx, pull_build_id)
    assert pull_build["buildStatus"] == "SUCCEEDED", f"pull+build failed: {pull_build}"

    resp = ecr.describe_images(repositoryName=final_repo_name, imageIds=[{"imageTag": "derived"}])
    details = resp["imageDetails"]
    assert len(details) == 1, f"expected exactly 1 image tagged 'derived', got {details}"
    assert "derived" in details[0]["imageTags"], (
        f"expected tag 'derived' in {details[0]['imageTags']}"
    )


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


def _create_ecr_repo(ctx: Any, name: str) -> str:
    ecr = ctx.client("ecr")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}]
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
        Tags=[{"Key": "sim2real", "Value": name}],
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


def _create_codebuild_project(
    ctx: Any,
    name: str,
    role_arn: str,
    buildspec: str,
    env_vars: dict[str, str] | None = None,
    privileged: bool = True,
    retries: int = 6,
    delay: float = 10.0,
) -> str:
    from botocore.exceptions import ClientError

    cb = ctx.client("codebuild")
    env_list = [{"name": k, "value": v, "type": "PLAINTEXT"} for k, v in (env_vars or {}).items()]
    kwargs: dict[str, Any] = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": buildspec},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
            "privilegedMode": privileged,
            "environmentVariables": env_list,
        },
        "serviceRole": role_arn,
        "tags": [{"key": "sim2real", "value": CHECK}],
    }

    last_err = None
    for _ in range(retries):
        try:
            cb.create_project(**kwargs)
            break
        except ClientError as e:
            # IAM role/policy propagation into CodeBuild's control plane is eventually
            # consistent; CreateProject rejects a too-new service role with this code.
            last_err = e
            if e.response["Error"]["Code"] == "InvalidInputException":
                time.sleep(delay)
                continue
            raise
    else:
        raise last_err  # type: ignore[misc]

    ctx.on_cleanup(lambda: cb.delete_project(name=name))
    return name


def _start_build(
    ctx: Any,
    project_name: str,
    overrides: dict[str, str] | None = None,
    buildspec_override: str | None = None,
    retries: int = 6,
    delay: float = 10.0,
) -> str:
    from botocore.exceptions import ClientError

    cb = ctx.client("codebuild")
    kwargs: dict[str, Any] = {"projectName": project_name}
    if overrides:
        kwargs["environmentVariablesOverride"] = [
            {"name": k, "value": v, "type": "PLAINTEXT"} for k, v in overrides.items()
        ]
    if buildspec_override:
        kwargs["buildspecOverride"] = buildspec_override

    last_err = None
    for _ in range(retries):
        try:
            return cb.start_build(**kwargs)["build"]["id"]
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidInputException":
                time.sleep(delay)
                continue
            raise
    raise last_err  # type: ignore[misc]


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
