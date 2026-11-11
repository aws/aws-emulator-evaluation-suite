"""stop-build-race-idempotent-single-transition."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-build-race-idempotent-single-transition"
GROUP = "concurrency"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent StopBuild calls on the same in-progress build are both accepted, and every
    STOPPED success carries the same endTime: the calls observe one shared transition, and the
    build settles in STOPPED with that endTime unchanged."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 90\n"
    project = _create_minimal_project(ctx, role_arn, buildspec)

    build_id = codebuild.start_build(projectName=project)["build"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, build_id))

    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0]["currentPhase"],
        lambda phase: phase == "BUILD",
        timeout_s=240.0,
        interval_s=3.0,
    )

    def _stop():
        return codebuild.stop_build(id=build_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_stop) for _ in range(2)]
        outcomes = []
        for f in futures:
            try:
                outcomes.append(("ok", f.result()))
            except ClientError as e:
                outcomes.append(("err", e))

    successes = [payload for kind, payload in outcomes if kind == "ok"]
    errors = [payload for kind, payload in outcomes if kind == "err"]

    assert not errors, (
        f"StopBuild is idempotent under a race on real AWS; both racing calls should "
        f"succeed, got {len(errors)} error(s): "
        f"{[e.response['Error']['Code'] for e in errors]}"
    )
    assert len(successes) == 2, f"expected both racing StopBuild calls to succeed, got {successes!r}"
    for build in successes:
        status = build["build"]["buildStatus"]
        assert status in ("STOPPED", "STOPPING"), f"unexpected racing buildStatus: {status}"

    stopped_end_times = {
        build["build"]["endTime"] for build in successes if build["build"]["buildStatus"] == "STOPPED"
    }
    assert len(stopped_end_times) <= 1, (
        f"racing StopBuild calls reported STOPPED with different endTimes "
        f"{stopped_end_times} — that is two independent transitions, not one"
    )

    final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b["buildComplete"],
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert final["buildStatus"] == "STOPPED"
    assert final["endTime"] is not None
    if stopped_end_times:
        (raced_end_time,) = stopped_end_times
        assert final["endTime"] == raced_end_time, (
            f"final endTime {final['endTime']} differs from the endTime {raced_end_time} "
            f"already observed mid-race — the terminal state advanced after settling"
        )


# ===== helpers =====
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
