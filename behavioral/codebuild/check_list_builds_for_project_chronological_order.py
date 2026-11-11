"""list-builds-for-project-chronological-order."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-builds-for-project-chronological-order"
GROUP = "ordering"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListBuildsForProject defaults to most-recent-build-number-first ordering."""
    codebuild = ctx.client("codebuild")
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(ctx, role_arn, _QUICK_BUILDSPEC)

    build_ids = []
    for _ in range(3):
        # buildNumber is assigned atomically in call order; each start_build only begins once the
        # previous one has returned, so no inter-call delay is needed to keep the numbers (and hence
        # the ordering) distinct.
        build = codebuild.start_build(projectName=project_name)["build"]
        build_ids.append(build["id"])
        ctx.on_cleanup(lambda bid=build["id"]: _try(lambda: codebuild.stop_build(id=bid)))

    def _all_listed() -> list[str] | None:
        ids = codebuild.list_builds_for_project(projectName=project_name).get("ids", [])
        return ids if len(ids) >= len(build_ids) else None

    listed = _poll_until(_all_listed, timeout_s=180, interval_s=3)
    assert listed is not None, "not all started builds appeared in ListBuildsForProject in time"
    assert set(listed) == set(build_ids), f"expected exactly {build_ids}, got {listed}"

    # Default sort order is DESCENDING by build number => most recently started build first.
    expected_order = list(reversed(build_ids))
    assert listed == expected_order, f"expected {expected_order}, got {listed}"

    # Explicit DESCENDING must match the default, ASCENDING must be its exact reverse.
    desc = codebuild.list_builds_for_project(projectName=project_name, sortOrder="DESCENDING")["ids"]
    asc = codebuild.list_builds_for_project(projectName=project_name, sortOrder="ASCENDING")["ids"]
    assert desc == expected_order, f"explicit DESCENDING {desc} must match default {expected_order}"
    assert asc == list(reversed(expected_order)), f"ASCENDING {asc} must reverse DESCENDING {expected_order}"

    # The delete is otherwise cleanup-only and unasserted: prove the builds gone and unusable.
    # BatchDeleteBuilds silently no-ops on a build that has not reached a terminal
    # state (confirmed against real AWS: an in-progress/queued build survives the
    # call with no error), so stop each build and wait for a terminal buildStatus
    # before deleting.
    for bid in build_ids:
        _try(lambda bid=bid: codebuild.stop_build(id=bid))

    def _all_terminal() -> list[dict] | None:
        builds = codebuild.batch_get_builds(ids=build_ids)["builds"]
        if len(builds) < len(build_ids):
            return None
        if all(b["buildStatus"] != "IN_PROGRESS" for b in builds):
            return builds
        return None

    terminal_builds = _poll_until(_all_terminal, timeout_s=120, interval_s=3)
    assert terminal_builds is not None, "builds did not reach a terminal state before delete"

    # BatchDeleteBuilds has its own, laggier notion of "in progress" than
    # BatchGetBuilds's buildStatus/buildComplete: confirmed against real AWS,
    # BatchDeleteBuilds can report every id BUILD_IN_PROGRESS in buildsNotDeleted
    # for tens of seconds after buildComplete has already flipped True. Retry the
    # delete itself (idempotent) rather than trusting the terminal read above.
    def _try_delete() -> dict | None:
        resp = codebuild.batch_delete_builds(ids=build_ids)
        return resp if resp["buildsNotDeleted"] == [] else None

    delete_resp = _poll_until(_try_delete, timeout_s=120, interval_s=5)
    assert delete_resp is not None, (
        f"BatchDeleteBuilds still refusing after 120s: "
        f"{codebuild.batch_delete_builds(ids=build_ids)['buildsNotDeleted']}"
    )

    after_delete = codebuild.batch_get_builds(ids=build_ids)
    assert after_delete["builds"] == [], f"expected no builds after delete, got {after_delete['builds']}"
    assert set(after_delete["buildsNotFound"]) == set(build_ids), (
        f"expected all deleted ids in buildsNotFound, got {after_delete['buildsNotFound']}"
    )
    dead_id = build_ids[0]
    code, message = _client_error(lambda: codebuild.stop_build(id=dead_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException stopping deleted build, got {code!r}"
    assert message == f"Build {dead_id} does not exist", message


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


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = probe()
        if value is not None:
            return value
        time.sleep(interval_s)
    return None


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
                    "ssmmessages:*",
                    "ssm:StartSession",
                    "codebuild:*",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    # No fixed propagation sleep here: _create_no_source_project's own bounded
    # retry loop (deadline 90s, catches InvalidInputException) already absorbs
    # IAM trust-policy propagation delay when the project is created below.
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
        assert last_err is not None, "create_project retry loop exited with no recorded error"
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
