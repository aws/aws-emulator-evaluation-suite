"""list-builds-for-project-returns-most-recent-first."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-builds-for-project-returns-most-recent-first"
GROUP = "ordering"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListBuildsForProject returns build ids ordered by start time descending
    (most recently started build first), matching CodeBuild's documented default
    ordering guarantee."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 20\n"
    project = _create_minimal_project(ctx, role_arn, buildspec)

    build1 = codebuild.start_build(projectName=project)["build"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, build1))
    # Wait for build1 to leave the queue before starting build2, so the two builds have a
    # genuine, observable causal order instead of relying on a fixed sleep to outrun a
    # possible same-timestamp tie.
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build1])["builds"][0].get("currentPhase"),
        lambda phase: phase != "SUBMITTED",
        timeout_s=60.0,
        interval_s=2.0,
    )
    build2 = codebuild.start_build(projectName=project)["build"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, build2))

    ids = _poll_until(
        lambda: codebuild.list_builds_for_project(projectName=project)["ids"],
        lambda ids: build1 in ids and build2 in ids,
        timeout_s=60.0,
        interval_s=3.0,
    )
    pos1 = ids.index(build1)
    pos2 = ids.index(build2)
    assert pos2 < pos1, f"expected later-started build2 before build1 in {ids}"


_ROLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ROLE_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "codebuild:StartBuild",
                    "codebuild:StopBuild",
                    "codebuild:RetryBuild",
                    "codebuild:BatchGetBuilds",
                    "codebuild:BatchGetProjects",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": role_arn,
                "Condition": {"StringEquals": {"iam:PassedToService": "codebuild.amazonaws.com"}},
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-cb-inline", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-inline"))
    return role_arn


def _create_minimal_project(ctx, role_arn: str, buildspec: str, extra: dict | None = None) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    params: dict = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": buildspec},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role_arn,
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    if extra:
        params.update(extra)
    deadline = time.monotonic() + 90.0
    while True:
        try:
            codebuild.create_project(**params)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    ctx.on_cleanup(lambda: codebuild.delete_project(name=name))
    return name


def _poll_until(probe, predicate, *, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _best_effort_stop(codebuild, build_id: str) -> None:
    try:
        codebuild.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
