"""build-queue-timeout-in-minutes-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "build-queue-timeout-in-minutes-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codebuild"]
_SCENARIO = CHECK


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/codebuild/latest/APIReference/API_StartBuild.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A build whose queuedTimeoutInMinutes elapses while waiting for a full
    reserved-capacity fleet transitions to buildStatus TIMED_OUT (phase
    COMPLETED) rather than remaining queued indefinitely."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)

    fleet_name = ctx.unique_name("sim2real-cb-fleet-")
    fleet_arn = codebuild.create_fleet(
        name=fleet_name,
        baseCapacity=1,
        environmentType="LINUX_CONTAINER",
        computeType="BUILD_GENERAL1_SMALL",
        overflowBehavior="QUEUE",
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )["fleet"]["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_fleet(arn=fleet_arn))

    fleet_status = _poll_until(
        lambda: codebuild.batch_get_fleets(names=[fleet_name])["fleets"][0]["status"]["statusCode"],
        lambda code: code in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert fleet_status == "ACTIVE", f"fleet failed to become ACTIVE: {fleet_status}"

    holder_buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 600\n"
    project = _create_minimal_project(
        ctx,
        role_arn,
        holder_buildspec,
        extra={
            "environment": {
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "fleet": {"fleetArn": fleet_arn},
            }
        },
    )

    holder_id = codebuild.start_build(projectName=project)["build"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, holder_id))
    # BatchGetFleets reporting ACTIVE means the fleet record exists, not that its EC2
    # instance has finished launching (the console's own setup flow has a distinct "wait
    # for the fleet instance to launch" step after fleet creation, before it shows n/n
    # capacity). Measured on real AWS: the first build against a freshly-ACTIVE fleet sat
    # QUEUED past 300s waiting for that instance to come up, so this bound is wider than
    # the fleet-status poll above on purpose.
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[holder_id])["builds"][0]["currentPhase"],
        lambda phase: phase == "BUILD",
        timeout_s=600.0,
        interval_s=5.0,
    )

    queued_id = codebuild.start_build(projectName=project, queuedTimeoutInMinutesOverride=5)["build"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, queued_id))

    queued_build = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[queued_id])["builds"][0],
        lambda b: b["currentPhase"] == "QUEUED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert queued_build["currentPhase"] == "QUEUED", (
        f"expected the second build to be QUEUED behind the full fleet, got {queued_build['currentPhase']!r}"
    )
    queued_since = time.monotonic()

    # AWS CodeBuild documents a 5-minute minimum for queuedTimeoutInMinutes; poll
    # past that documented window and then assert the terminal transition landed
    # neither before the declared override (a target ignoring it and timing out
    # early) nor only past the outer poll deadline (a target never enforcing it).
    final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[queued_id])["builds"][0],
        lambda b: b["buildComplete"],
        timeout_s=8 * 60.0,
        interval_s=10.0,
    )
    elapsed_s = time.monotonic() - queued_since
    assert elapsed_s >= 4.5 * 60, (
        f"timed out after only {elapsed_s:.0f}s, before the 5-minute queuedTimeoutInMinutesOverride elapsed"
    )
    # Measured on real AWS: a build that exceeds queuedTimeoutInMinutes(Override) while
    # still QUEUED completes with buildStatus FAILED, not TIMED_OUT — TIMED_OUT is what
    # the overall buildStatus shows for the build's own execution timeoutInMinutes being
    # exceeded during an active phase, a different limit than the queue wait tested here.
    assert final["buildStatus"] == "FAILED", f"expected FAILED, got {final['buildStatus']!r}"
    assert final["currentPhase"] == "COMPLETED", f"expected COMPLETED, got {final['currentPhase']!r}"
    queued_phase = next((p for p in final["phases"] if p["phaseType"] == "QUEUED"), None)
    assert queued_phase is not None, f"no QUEUED phase in {final['phases']!r}"
    assert queued_phase["phaseStatus"] == "TIMED_OUT", (
        f"expected the QUEUED phase itself to report TIMED_OUT, got {queued_phase.get('phaseStatus')!r}"
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


def _best_effort_stop(codebuild, build_id: str) -> None:
    try:
        codebuild.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
