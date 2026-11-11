"""list-build-batches-ordered-by-start-time."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-build-batches-ordered-by-start-time"
GROUP = "ordering"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListBuildBatchesForProject documents ASCENDING and DESCENDING as orders "by identifier"
    without naming the key, so with two batches started a second apart, both orders list both
    ids and DESCENDING lists them in exactly the reverse of ASCENDING."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    buildspec = (
        "version: 0.2\n"
        "batch:\n"
        "  build-list:\n"
        "    - identifier: build1\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo hello\n"
    )
    extra = {
        "buildBatchConfig": {"serviceRole": role_arn},
        # no CloudWatch Logs group, which the builds would otherwise create and leave behind
        "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"}},
    }
    project = _create_minimal_project(ctx, role_arn, buildspec, extra=extra)

    batch1 = codebuild.start_build_batch(projectName=project)["buildBatch"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop_batch(codebuild, batch1))
    start1 = _wait_for_recorded_start(codebuild, batch1)
    # Give batch2 a startTime that provably postdates batch1's rather than
    # assuming a fixed sleep is long enough: wait for the wall clock itself
    # to pass batch1's own recorded startTime by a full second.
    _wait_past(start1)
    batch2 = codebuild.start_build_batch(projectName=project)["buildBatch"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop_batch(codebuild, batch2))
    start2 = _wait_for_recorded_start(codebuild, batch2)
    assert start2 > start1, (
        f"expected batch2's recorded startTime after batch1's, got batch1={start1!r} batch2={start2!r}"
    )

    _poll_until(
        lambda: codebuild.list_build_batches_for_project(projectName=project)["ids"],
        lambda ids: batch1 in ids and batch2 in ids,
        timeout_s=90.0,
        interval_s=3.0,
    )
    orders = {}
    for sort_order in ("ASCENDING", "DESCENDING"):
        ids = codebuild.list_build_batches_for_project(projectName=project, sortOrder=sort_order)[
            "ids"
        ]
        assert batch1 in ids and batch2 in ids, (
            f"expected {sort_order} to list {batch1} and {batch2}, got {ids}"
        )
        orders[sort_order] = [i for i in ids if i in (batch1, batch2)]
    assert orders["DESCENDING"] == orders["ASCENDING"][::-1], (
        f"expected DESCENDING to list the two batches in the reverse of ASCENDING, got {orders}"
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


def _wait_for_recorded_start(codebuild, batch_id: str, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = codebuild.batch_get_build_batches(ids=[batch_id])["buildBatches"][0]
        start_time = last.get("startTime")
        if start_time is not None:
            return start_time
        time.sleep(interval_s)
    raise AssertionError(
        f"batch {batch_id} did not report a startTime within {timeout_s}s; last observed={last!r}"
    )


def _wait_past(ts, *, margin_s: float = 1.0, timeout_s: float = 30.0, interval_s: float = 0.5) -> None:
    """Blocks until the wall clock is at least ``margin_s`` past ``ts``, so the
    next batch started is guaranteed a distinct, later recorded startTime."""
    target = ts + timedelta(seconds=margin_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if datetime.now(timezone.utc) >= target:
            return
        time.sleep(interval_s)
    raise AssertionError(f"wall clock did not advance past {target} within {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _best_effort_stop_batch(codebuild, batch_id: str) -> None:
    try:
        codebuild.stop_build_batch(id=batch_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
