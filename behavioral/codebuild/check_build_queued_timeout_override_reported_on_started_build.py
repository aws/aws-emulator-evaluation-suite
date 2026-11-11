"""build-queued-timeout-override-reported-on-started-build."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "build-queued-timeout-override-reported-on-started-build"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codebuild"]
_SCENARIO = CHECK

# queuedTimeoutInMinutes ranges from 5 to 480; the project and the override each set their own value.
_PROJECT_QUEUED_TIMEOUT_MIN = 7
_OVERRIDE_QUEUED_TIMEOUT_MIN = 5
#: Keeps each build in progress while it is read; teardown stops it.
_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 300\n"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An in-progress build started with queuedTimeoutInMinutesOverride=5 reports 5, a build
    started without one reports the project's queuedTimeoutInMinutes of 7, and an override of 4,
    below the minimum, is refused.

    Reference: https://docs.aws.amazon.com/codebuild/latest/APIReference/API_StartBuild.html
    """
    codebuild = ctx.client("codebuild")
    raw = ctx.client("codebuild", config=Config(parameter_validation=False))
    role_arn = _create_codebuild_role(ctx)

    project = _create_minimal_project(
        ctx, role_arn, _BUILDSPEC,
        extra={"queuedTimeoutInMinutes": _PROJECT_QUEUED_TIMEOUT_MIN},
    )
    reported = codebuild.batch_get_projects(names=[project])["projects"][0]["queuedTimeoutInMinutes"]
    assert reported == _PROJECT_QUEUED_TIMEOUT_MIN, (
        f"BatchGetProjects must echo queuedTimeoutInMinutes={_PROJECT_QUEUED_TIMEOUT_MIN}, got {reported!r}"
    )

    code, message = _start_refused(ctx, raw, project, queued_timeout_override=4)
    assert code == "InvalidInputException", (
        f"queuedTimeoutInMinutesOverride=4: expected InvalidInputException, got {code}: {message!r}"
    )
    expected = "Invalid queued timeout. Should be between 5 minutes and 8 hours"
    assert message == expected, (
        f"queuedTimeoutInMinutesOverride=4: expected message {expected!r}, got {message!r}"
    )

    plain_id = codebuild.start_build(projectName=project)["build"]["id"]
    ctx.on_cleanup(lambda: _stop_and_wait(codebuild, plain_id))
    override_id = codebuild.start_build(
        projectName=project, queuedTimeoutInMinutesOverride=_OVERRIDE_QUEUED_TIMEOUT_MIN
    )["build"]["id"]
    ctx.on_cleanup(lambda: _stop_and_wait(codebuild, override_id))

    builds = {b["id"]: b for b in codebuild.batch_get_builds(ids=[plain_id, override_id])["builds"]}
    plain, override = builds[plain_id], builds[override_id]
    assert plain["buildComplete"] is False and override["buildComplete"] is False, (
        f"both builds run a 300 s command and must still be in progress; got phases "
        f"{plain['currentPhase']!r} and {override['currentPhase']!r}"
    )
    assert plain["queuedTimeoutInMinutes"] == _PROJECT_QUEUED_TIMEOUT_MIN, (
        f"a build started without an override must report the project's queuedTimeoutInMinutes="
        f"{_PROJECT_QUEUED_TIMEOUT_MIN}, got {plain['queuedTimeoutInMinutes']!r}"
    )
    assert override["queuedTimeoutInMinutes"] == _OVERRIDE_QUEUED_TIMEOUT_MIN, (
        f"a build started with queuedTimeoutInMinutesOverride={_OVERRIDE_QUEUED_TIMEOUT_MIN} must "
        f"report it, got {override['queuedTimeoutInMinutes']!r}"
    )


def _start_refused(ctx, raw, project: str, *, queued_timeout_override: int):
    """StartBuild with an out-of-range override; return the refusal's (code, message).

    A build AWS starts anyway is stopped at cleanup and the call fails the check.
    """
    try:
        build_id = raw.start_build(
            projectName=project, queuedTimeoutInMinutesOverride=queued_timeout_override
        )["build"]["id"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    ctx.on_cleanup(lambda: _stop_and_wait(ctx.client("codebuild"), build_id))
    raise AssertionError(
        f"StartBuild accepted queuedTimeoutInMinutesOverride={queued_timeout_override} and started {build_id}"
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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
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


def _stop_and_wait(codebuild, build_id: str, timeout_s: float = 120.0) -> None:
    """Stop the build unless it already completed, then wait until it reports buildComplete."""
    found = codebuild.batch_get_builds(ids=[build_id])["builds"]
    if not found:
        return
    if not found[0]["buildComplete"]:
        try:
            codebuild.stop_build(id=build_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"],
        lambda got: not got or got[0]["buildComplete"],
        timeout_s=timeout_s,
        interval_s=5.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
