"""ecr-image-tag-matches-codebuild-generated-tag."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecr-image-tag-matches-codebuild-generated-tag"
GROUP = "image-delivery"
SERVICES = ["codebuild", "codepipeline", "ecr"]

# The buildspec derives the image tag itself (simulating "tag by commit hash") from the
# CodeBuild build id rather than receiving it as an input -- the test recomputes the same
# derivation independently from the build id returned by StartBuild and asserts ECR stored
# exactly that tag.
_BUILDSPEC_SELF_TAGGING = """version: 0.2
phases:
  pre_build:
    commands:
      - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $REPO_URI
      - export IMAGE_TAG=$(echo $CODEBUILD_BUILD_ID | cut -d ':' -f2 | cut -c1-8)
      - echo "computed image tag $IMAGE_TAG"
  build:
    commands:
      - printf 'FROM busybox\\nCMD ["echo","hi"]\\n' > Dockerfile
      - docker build -t $REPO_URI:$IMAGE_TAG .
  post_build:
    commands:
      - docker push $REPO_URI:$IMAGE_TAG
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """The tag a CodeBuild buildspec derives from its own build id matches what lands in ECR."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-tagmatch-")
    repo_uri = _create_ecr_repo(ctx, repo_name)
    role_arn = _create_codebuild_role(
        ctx, ctx.unique_name("sim2real-cbrole-"), _ECR_PUSH_ALL_STATEMENT
    )
    project = _create_codebuild_project(
        ctx,
        ctx.unique_name("sim2real-cbproj-"),
        role_arn,
        _BUILDSPEC_SELF_TAGGING,
        env_vars={"REPO_URI": repo_uri},
    )
    build_id = _start_build(ctx, project)
    build = _wait_for_build(ctx, build_id)
    assert build["buildStatus"] == "SUCCEEDED", f"build did not succeed: {build}"

    # CodeBuild build ids look like "<project>:<uuid>"; the buildspec derived its tag as
    # the first 8 characters of the uuid portion -- reproduce that exactly here.
    returned_id = build["id"]
    assert ":" in returned_id, f"expected '<project>:<uuid>' build id, got {returned_id!r}"
    expected_tag = returned_id.split(":", 1)[1][:8]

    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": expected_tag}])
    details = resp["imageDetails"]
    assert len(details) == 1, (
        f"expected exactly one image tagged {expected_tag!r} in {repo_name}, got {details}"
    )
    assert details[0]["imageTags"] == [expected_tag], (
        f"expected ECR image tags == [{expected_tag!r}], got {details[0]['imageTags']}"
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
    # CreateProject itself validates that CodeBuild can assume the service role, so it is
    # the trust policy just written in _create_codebuild_role that may not have propagated
    # yet -- bounded retry on the specific "not authorized to assume role" rejection.
    last_err = None
    for _ in range(retries):
        try:
            cb.create_project(**kwargs)
            break
        except ClientError as e:
            last_err = e
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "InvalidInputException" and "AssumeRole" in message:
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

    # Bounded retry, not a sleep before the call: the role/policy just created in
    # _create_codebuild_role may not have propagated yet, and CodeBuild reports that as
    # InvalidInputException on start_build rather than as an IAM error.
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
