"""codebuild-pushes-docker-image-to-ecr-repository."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "codebuild-pushes-docker-image-to-ecr-repository"
GROUP = "image-delivery"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A docker image built inside a CodeBuild project lands in the target ECR repo."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-imgdel-")
    repo_uri = _create_ecr_repo(ctx, repo_name)
    role_arn = _create_codebuild_role(
        ctx, ctx.unique_name("sim2real-cbrole-"), _ECR_PUSH_ALL_STATEMENT
    )
    tag = "v1"
    project = _create_codebuild_project(
        ctx,
        ctx.unique_name("sim2real-cbproj-"),
        role_arn,
        _BUILDSPEC_PUSH,
        env_vars={"REPO_URI": repo_uri, "IMAGE_TAG": tag},
    )
    build_id = _start_build(ctx, project)
    build = _wait_for_build(ctx, build_id)
    assert build["buildStatus"] == "SUCCEEDED", f"build did not succeed: {build}"

    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    details = resp["imageDetails"]
    assert len(details) == 1, f"expected exactly one image for tag {tag!r}, got {details}"
    assert details[0]["imageTags"] == [tag], f"expected imageTags == [{tag!r}], got {details[0]['imageTags']}"


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
    # IAM role/policy propagation lag is bounded by _start_build's own retry on the
    # transient AssumeRole rejection below, not by a fixed wait here.
    return role_arn


def _create_codebuild_project(
    ctx: Any,
    name: str,
    role_arn: str,
    buildspec: str,
    env_vars: dict[str, str] | None = None,
    privileged: bool = True,
) -> str:
    from botocore.exceptions import ClientError

    cb = ctx.client("codebuild")
    env_list = [{"name": k, "value": v, "type": "PLAINTEXT"} for k, v in (env_vars or {}).items()]
    kwargs = dict(
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
    # CreateProject validates the service role's trust policy synchronously, so a role
    # created moments ago is retried through IAM's propagation lag here, not at StartBuild.
    deadline = time.monotonic() + 90
    while True:
        try:
            cb.create_project(**kwargs)
            break
        except ClientError as e:
            err = e.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
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
            err = e.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role:
                time.sleep(delay)  # bounded retry through IAM role/policy propagation lag
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
