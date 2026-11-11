"""codebuild-missing-ecr-login-fails-docker-push."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "codebuild-missing-ecr-login-fails-docker-push"
GROUP = "auth-flow"
SERVICES = ["codebuild", "codepipeline", "ecr"]

_BUILDSPEC_WITH_LOGIN = """version: 0.2
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

# Identical except the docker-login step before the push is skipped entirely.
_BUILDSPEC_WITHOUT_LOGIN = """version: 0.2
phases:
  build:
    commands:
      - printf 'FROM busybox\\nCMD ["echo","hi"]\\n' > Dockerfile
      - docker build -t $REPO_URI:$IMAGE_TAG .
  post_build:
    commands:
      - docker push $REPO_URI:$IMAGE_TAG
"""

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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Skipping the `docker login` step makes `docker push` fail even with an IAM-permissive role."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-nologin-")
    repo_uri = _create_ecr_repo(ctx, repo_name)
    # Role has every push permission ECR requires -- the only thing missing is the login step.
    role_arn = _create_codebuild_role(
        ctx, ctx.unique_name("sim2real-cbrole-"), _ECR_PUSH_ALL_STATEMENT
    )
    project = _create_codebuild_project(
        ctx, ctx.unique_name("sim2real-cbproj-"), role_arn, _BUILDSPEC_WITH_LOGIN
    )

    # --- negative: no docker login before push ---
    no_login_build = _wait_for_build(
        ctx,
        _start_build(
            ctx,
            project,
            overrides={"REPO_URI": repo_uri, "IMAGE_TAG": "no-login"},
            buildspec_override=_BUILDSPEC_WITHOUT_LOGIN,
        ),
    )
    assert no_login_build["buildStatus"] == "FAILED", f"expected FAILED, got {no_login_build}"

    code, message = _error(
        lambda: ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "no-login"}])
    )
    assert code == "ImageNotFoundException", f"expected ImageNotFoundException, got {code}"
    expected_message = (
        f"The image with imageId {{imageDigest:'null', imageTag:'no-login'}} does not exist "
        f"within the repository with name '{repo_name}' in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- positive control: same role and project, login step present ---
    login_build = _wait_for_build(
        ctx,
        _start_build(ctx, project, overrides={"REPO_URI": repo_uri, "IMAGE_TAG": "with-login"}),
    )
    assert login_build["buildStatus"] == "SUCCEEDED", f"control build failed: {login_build}"

    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "with-login"}])
    assert "with-login" in resp["imageDetails"][0]["imageTags"], (
        f"expected tag 'with-login' on pushed image, got {resp['imageDetails'][0]['imageTags']}"
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
    # No sleep here: trust-policy propagation to the CodeBuild/AssumeRole data plane is
    # bounded instead by the retries in _create_codebuild_project and _start_build below.
    return role_arn


def _create_codebuild_project(
    ctx: Any,
    name: str,
    role_arn: str,
    buildspec: str,
    env_vars: dict[str, str] | None = None,
    privileged: bool = True,
    timeout_s: float = 90.0,
    delay: float = 3.0,
) -> str:
    from botocore.exceptions import ClientError

    cb = ctx.client("codebuild")
    env_list = [{"name": k, "value": v, "type": "PLAINTEXT"} for k, v in (env_vars or {}).items()]
    kwargs: dict[str, Any] = dict(
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
    # Bounded retry for IAM trust-policy propagation: CreateProject validates the role can
    # be assumed and can 400 for a few seconds right after create_role/put_role_policy.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cb.create_project(**kwargs)
            break
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "InvalidInputException" and "AssumeRole" in err.get(
                "Message", ""
            ) and time.monotonic() < deadline:
                time.sleep(delay)
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

    # Bounded retry (up to retries * delay = 60s) for IAM trust-policy propagation: a role
    # created moments ago can still make AssumeRole answer InvalidInputException.
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
