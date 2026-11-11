"""batch-delete-builds-partial-failure-isolated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-builds-partial-failure-isolated"
GROUP = "concurrency"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDeleteBuilds with a completed and an IN_PROGRESS build deletes the completed one and lists the
    running one in buildsNotDeleted; the deleted build is then not found, and the other deletes once
    it has stopped."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    fast_spec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo fast\n"
    slow_spec = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 90\n      - echo slow\n"
    project = _create_minimal_project(ctx, role_arn, fast_spec)

    build_fast = codebuild.start_build(projectName=project, buildspecOverride=fast_spec)["build"]["id"]
    build_slow = codebuild.start_build(projectName=project, buildspecOverride=slow_spec)["build"]["id"]
    ctx.on_cleanup(lambda: codebuild.batch_delete_builds(ids=[build_slow]))

    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_fast])["builds"],
        lambda builds: len(builds) == 1 and builds[0]["buildComplete"],
        timeout_s=300.0,
        interval_s=5.0,
    )

    # independent read confirming the twin control is genuinely still running at this
    # instant, so a target with no in-progress protection at all cannot score green
    still_running = codebuild.batch_get_builds(ids=[build_slow])["builds"]
    assert len(still_running) == 1 and not still_running[0]["buildComplete"], (
        f"expected build_slow ({build_slow!r}) still in progress at the moment of the mixed delete, got {still_running!r}"
    )

    mixed = codebuild.batch_delete_builds(ids=[build_fast, build_slow])
    # BatchDeleteBuilds echoes back the build's full ARN in buildsDeleted, not the bare
    # id passed in, despite the API doc's "The IDs of the builds" wording.
    assert len(mixed["buildsDeleted"]) == 1 and mixed["buildsDeleted"][0].endswith(build_fast), (
        f"expected only the completed build_fast ({build_fast!r}) deleted from the mixed batch, got {mixed['buildsDeleted']!r}"
    )
    not_deleted_ids = [d["id"] for d in mixed["buildsNotDeleted"]]
    assert len(not_deleted_ids) == 1 and not_deleted_ids[0].endswith(build_slow), (
        f"expected the still-running build_slow ({build_slow!r}) reported in buildsNotDeleted, got {mixed['buildsNotDeleted']!r}"
    )

    after = codebuild.batch_get_builds(ids=[build_fast])
    assert after["builds"] == [], f"expected build_fast ({build_fast!r}) gone after delete, still present: {after['builds']!r}"
    # buildsNotFound shares BatchDeleteBuilds's BuildIds shape, which is ARN-valued in
    # practice despite the "IDs" doc wording (see buildsDeleted above); match by suffix.
    assert len(after["buildsNotFound"]) == 1 and after["buildsNotFound"][0].endswith(build_fast), (
        f"expected buildsNotFound to report build_fast ({build_fast!r}), got {after['buildsNotFound']!r}"
    )

    # the withheld build is still deletable once it actually reaches a terminal state
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_slow])["builds"],
        lambda builds: len(builds) == 1 and builds[0]["buildComplete"],
        timeout_s=180.0,
        interval_s=5.0,
    )
    final = codebuild.batch_delete_builds(ids=[build_slow])
    assert len(final["buildsDeleted"]) == 1 and final["buildsDeleted"][0].endswith(build_slow), (
        f"expected build_slow ({build_slow!r}) deletable once complete, got {final!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
