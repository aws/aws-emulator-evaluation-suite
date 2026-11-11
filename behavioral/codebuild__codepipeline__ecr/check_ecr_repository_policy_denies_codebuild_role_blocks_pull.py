"""ecr-repository-policy-denies-codebuild-role-blocks-pull."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecr-repository-policy-denies-codebuild-role-blocks-pull"
GROUP = "permission-boundary"
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

# Pulls the already-pushed base tag, then re-tags and pushes a "pull-verified" marker tag
# so success/failure of the pull is directly observable as presence/absence of that tag.
_BUILDSPEC_PULL_AND_VERIFY = """version: 0.2
phases:
  pre_build:
    commands:
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $REPO_URI
  build:
    commands:
      - docker pull $REPO_URI:base
      - docker tag $REPO_URI:base $REPO_URI:pull-verified
  post_build:
    commands:
      - docker push $REPO_URI:pull-verified
"""

_ECR_FULL_STATEMENT = {
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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit ECR repository-policy Deny for a role blocks its pull despite an IAM Allow, and
    removing the Deny makes the identical pull succeed again."""
    ecr = ctx.client("ecr")
    denied_repo_name = ctx.unique_name("sim2real-denyrepo-")
    allowed_repo_name = ctx.unique_name("sim2real-allowrepo-")
    denied_uri = _create_ecr_repo(ctx, denied_repo_name)
    allowed_uri = _create_ecr_repo(ctx, allowed_repo_name)

    # IAM alone grants this role full push+pull on both repos.
    role_arn = _create_codebuild_role(
        ctx, ctx.unique_name("sim2real-cbrole-"), _ECR_FULL_STATEMENT
    )
    project = _create_codebuild_project(
        ctx, ctx.unique_name("sim2real-cbproj-"), role_arn, _BUILDSPEC_PUSH_BASE
    )

    # Seed both repos with a base image while no repository policy exists yet.
    for uri in (denied_uri, allowed_uri):
        setup_build = _wait_for_build(
            ctx, _start_build(ctx, project, overrides={"REPO_URI": uri})
        )
        assert setup_build["buildStatus"] == "SUCCEEDED", f"seed push failed: {setup_build}"

    # Attach a repository policy on denied_repo that explicitly denies THIS role's pull actions.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyPullForCodeBuildRole",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
            }
        ],
    }
    ecr.set_repository_policy(repositoryName=denied_repo_name, policyText=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _drop_policy(ecr, denied_repo_name))

    # --- negative: pull from the denied repo is blocked despite the IAM Allow ---
    denied_build = _wait_for_build(
        ctx,
        _start_build(
            ctx,
            project,
            overrides={"REPO_URI": denied_uri},
            buildspec_override=_BUILDSPEC_PULL_AND_VERIFY,
        ),
    )
    assert denied_build["buildStatus"] == "FAILED", f"expected FAILED, got {denied_build}"

    code, message = _error(
        lambda: ecr.describe_images(
            repositoryName=denied_repo_name, imageIds=[{"imageTag": "pull-verified"}]
        )
    )
    assert code == "ImageNotFoundException", (
        f"a build the repository-policy Deny blocked must never have pushed the pull-verified "
        f"marker tag; describe_images answered with error code {code!r} instead of "
        f"ImageNotFoundException"
    )
    expected_message = (
        f"The image with imageId {{imageDigest:'null', imageTag:'pull-verified'}} does not exist "
        f"within the repository with name '{denied_repo_name}' in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- restore: removing the Deny makes the IDENTICAL pull-and-verify call succeed again ---
    ecr.delete_repository_policy(repositoryName=denied_repo_name)
    restored_build = _wait_for_build(
        ctx,
        _start_build(
            ctx,
            project,
            overrides={"REPO_URI": denied_uri},
            buildspec_override=_BUILDSPEC_PULL_AND_VERIFY,
        ),
    )
    assert restored_build["buildStatus"] == "SUCCEEDED", (
        f"the identical pull-and-verify build must succeed once the Deny is removed, got "
        f"{restored_build}"
    )
    restored_resp = ecr.describe_images(
        repositoryName=denied_repo_name, imageIds=[{"imageTag": "pull-verified"}]
    )
    assert "pull-verified" in restored_resp["imageDetails"][0]["imageTags"], (
        f"after DeleteRepositoryPolicy the marker tag is still missing from "
        f"{restored_resp['imageDetails'][0]['imageTags']!r}"
    )

    # --- positive control: same role, same buildspec, a repo that never had the deny statement ---
    allowed_build = _wait_for_build(
        ctx,
        _start_build(
            ctx,
            project,
            overrides={"REPO_URI": allowed_uri},
            buildspec_override=_BUILDSPEC_PULL_AND_VERIFY,
        ),
    )
    assert allowed_build["buildStatus"] == "SUCCEEDED", f"control build failed: {allowed_build}"

    resp = ecr.describe_images(
        repositoryName=allowed_repo_name, imageIds=[{"imageTag": "pull-verified"}]
    )
    assert "pull-verified" in resp["imageDetails"][0]["imageTags"], (
        f"the control build pushed pull-verified but it is missing from "
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


def _drop_policy(ecr, name):
    """Teardown-only: tolerate the policy already being gone (the body deletes it as part of the
    restore leg) or the repository already being gone (repo cleanup can race this one)."""
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository_policy(repositoryName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "RepositoryPolicyNotFoundException",
            "RepositoryNotFoundException",
        ):
            raise


def _create_ecr_repo(ctx: Any, name: str) -> str:
    ecr = ctx.client("ecr")
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real", "Value": "ecr-repository-policy-denies-codebuild-role-blocks-pull"}],
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
        Tags=[{"Key": "sim2real", "Value": "ecr-repository-policy-denies-codebuild-role-blocks-pull"}],
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
            tags=[
                {"key": "sim2real", "value": "ecr-repository-policy-denies-codebuild-role-blocks-pull"}
            ],
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
