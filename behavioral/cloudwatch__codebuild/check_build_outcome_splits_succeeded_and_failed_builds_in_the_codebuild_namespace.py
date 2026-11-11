"""build-outcome-splits-succeeded-and-failed-builds-in-the-codebuild-namespace."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "build-outcome-splits-succeeded-and-failed-builds-in-the-codebuild-namespace"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "codebuild"]

# CodeBuild does not document its publication cadence; 900s assumes it is no slower than 5 min.
_METRIC_BUDGET_S = 900.0
_BUILD_BUDGET_S = 600.0
_ROLE_PROPAGATION_BUDGET_S = 180.0

_SUCCEED_BUILDSPEC = json.dumps(
    {
        "version": "0.2",
        "phases": {"build": {"commands": ["echo sim2real-cwcb-success", "exit 0"]}},
    }
)
_FAIL_BUILDSPEC = json.dumps(
    {
        "version": "0.2",
        "phases": {"build": {"commands": ["echo sim2real-cwcb-failure", "exit 1"]}},
    }
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """One succeeding and one failing build on one project count separately in AWS/CodeBuild.
    SucceededBuilds and FailedBuilds are each 1 (not 2/0), Builds is 2, units are Count/Seconds, and
    Duration Maximum is bounded by the builds' own BatchGetBuilds start/end windows.
    """
    cb = ctx.client("codebuild")
    cw = ctx.client("cloudwatch")

    role_arn = _codebuild_role(ctx)
    project = ctx.unique_name("sim2real-cwcb-")[:255]
    log_group = f"/aws/codebuild/{project}"

    _retry_on_role_propagation(
        ctx,
        lambda: cb.create_project(
            name=project,
            source={"type": "NO_SOURCE", "buildspec": _SUCCEED_BUILDSPEC},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            tags=[{"key": "sim2real", "value": "cloudwatch__codebuild"}],
        ),
        description=f"CreateProject {project} accepting the freshly created role {role_arn}",
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project))
    # CodeBuild creates this log group on the first build; delete it so the run leaks nothing.
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=log_group))

    good = _run_build(ctx, cb, project, buildspec=None, want="SUCCEEDED")
    bad = _run_build(ctx, cb, project, buildspec=_FAIL_BUILDSPEC, want="FAILED")

    good_seconds = (good["endTime"] - good["startTime"]).total_seconds()
    bad_seconds = (bad["endTime"] - bad["startTime"]).total_seconds()
    assert good_seconds > 0 and bad_seconds > 0, (
        f"CodeBuild reported non-positive build windows (good {good_seconds}s, bad {bad_seconds}s); "
        f"the Duration bound below is derived from those windows and cannot be computed"
    )
    longest_seconds = max(good_seconds, bad_seconds)

    window_start = datetime.now(timezone.utc) - timedelta(minutes=40)

    def _dps(metric: str) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace="AWS/CodeBuild",
            MetricName=metric,
            Dimensions=[{"Name": "ProjectName", "Value": project}],
            StartTime=window_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum", "Maximum", "SampleCount"],
        )["Datapoints"]

    def _sum(metric: str) -> float | None:
        dps = _dps(metric)
        return float(sum(d["Sum"] for d in dps)) if dps else None

    succeeded, failed = _poll_until_stable(
        lambda: _pair(_sum("SucceededBuilds"), _sum("FailedBuilds")),
        window_s=5.0,
        timeout_s=_budget_s(ctx, _METRIC_BUDGET_S), ctx=ctx,
        interval_s=1.0,
        description=(
            f"AWS/CodeBuild SucceededBuilds and FailedBuilds for ProjectName={project} settling on "
            f"one value"
        ),
    )
    assert succeeded == 1.0, (
        f"AWS/CodeBuild SucceededBuilds Sum for ProjectName={project} settled at {succeeded!r}, "
        f"expected 1.0 — this project ran exactly one build that CodeBuild itself reported as "
        f"SUCCEEDED (build {good['id']})"
    )
    assert failed == 1.0, (
        f"AWS/CodeBuild FailedBuilds Sum for ProjectName={project} settled at {failed!r}, expected "
        f"1.0 — exactly one build exited 1 and CodeBuild reported it FAILED (build {bad['id']})"
    )
    assert succeeded != 2.0 and failed != 2.0, (
        f"SucceededBuilds={succeeded!r} FailedBuilds={failed!r} for ProjectName={project}: a value "
        f"of 2 on either counter means both builds were credited to one outcome, which is the "
        f"single most likely wrong implementation and is invisible to any check that reads only "
        f"BatchGetBuilds' own buildStatus"
    )

    builds_total = _sum("Builds")
    assert builds_total == 2.0, (
        f"AWS/CodeBuild Builds Sum for ProjectName={project} read {builds_total!r}, expected 2.0 — "
        f"the project ran two builds. If real AWS excludes failed builds from `Builds`, the honest "
        f"contract is Builds == SucceededBuilds + FailedBuilds and this assertion must be re-cut to "
        f"that (see H2), not deleted"
    )

    for metric, want_unit in (
        ("Builds", "Count"),
        ("SucceededBuilds", "Count"),
        ("FailedBuilds", "Count"),
    ):
        dps = _dps(metric)
        assert dps, f"AWS/CodeBuild {metric} vanished on re-read for ProjectName={project}: {dps!r}"
        units = {d.get("Unit") for d in dps}
        assert units == {want_unit}, (
            f"AWS/CodeBuild {metric} datapoints for ProjectName={project} carry Unit(s) {units!r}, "
            f"expected exactly {{{want_unit!r}}}"
        )

    # Duration is bounded by the builds' own reported windows, not a literal.
    duration = _dps("Duration")
    assert duration, (
        f"AWS/CodeBuild Duration has no datapoint for ProjectName={project} although two builds "
        f"completed; Duration is the metric every build-slowness alarm is built on"
    )
    units = {d.get("Unit") for d in duration}
    assert units == {"Seconds"}, (
        f"AWS/CodeBuild Duration datapoints for ProjectName={project} carry Unit(s) {units!r}, "
        f"expected exactly {{'Seconds'}} — a duration reported in Milliseconds or Count makes every "
        f"threshold on it wrong by three orders of magnitude"
    )
    observed_max = max(d["Maximum"] for d in duration)
    ceiling = longest_seconds + 60.0
    assert 0.0 < observed_max <= ceiling, (
        f"AWS/CodeBuild Duration Maximum for ProjectName={project} is {observed_max!r}s; CodeBuild's "
        f"OWN BatchGetBuilds reported windows of {good_seconds:.0f}s and {bad_seconds:.0f}s for the "
        f"two builds, so the published maximum cannot exceed {ceiling:.0f}s. A constant, a zero, or "
        f"a value in the wrong unit fails this bound while a genuinely slow build passes it"
    )

    # ListMetrics lists a new series later than GetMetricStatistics returns its datapoints; poll
    # until the per-project series is listed, then assert on the last read.
    deadline = time.monotonic() + _budget_s(ctx, _METRIC_BUDGET_S)
    sets = _dimension_sets(cw, "AWS/CodeBuild", "ProjectName", project)
    while ("ProjectName",) not in sets and time.monotonic() < deadline:
        time.sleep(2.0)
        sets = _dimension_sets(cw, "AWS/CodeBuild", "ProjectName", project)
    if ("ProjectName",) not in sets and _budget_spent(ctx):
        raise TimeoutError(
            f"ListMetrics to list the ProjectName={project} series: the run budget ended first; "
            f"not graded"
        )
    assert ("ProjectName",) in sets, (
        f"ListMetrics reports dimension sets {sorted(sets)!r} for the AWS/CodeBuild series naming "
        f"ProjectName={project}; the per-project ('ProjectName',) series must exist, because the "
        f"account-level series cannot tell one project's failures from another's"
    )


def _codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-cwcb-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codebuild.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__codebuild"}],
    )["Role"]["Arn"]
    policy_name = "sim2real-codebuild-logs"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": f"arn:aws:logs:{ctx.region}:{account}:log-group:/aws/codebuild/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return arn


def _run_build(ctx, cb, project: str, *, buildspec: str | None, want: str) -> dict:
    kwargs: dict = {"projectName": project}
    if buildspec is not None:
        kwargs["buildspecOverride"] = buildspec
    build_id = cb.start_build(**kwargs)["build"]["id"]
    build = _poll_until(
        lambda: cb.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b.get("buildComplete") is True and b.get("buildStatus") != "IN_PROGRESS",
        timeout_s=_budget_s(ctx, _BUILD_BUDGET_S), ctx=ctx,
        interval_s=1.0,
        description=f"build {build_id} on {project} completing (expected {want})",
    )
    assert build["buildStatus"] == want, (
        f"build {build_id} on {project} ended with buildStatus {build['buildStatus']!r}, expected "
        f"{want!r}; the per-outcome metric totals asserted later are only attributable to builds "
        f"whose outcome CodeBuild itself confirms. Phases were "
        f"{[(p.get('phaseType'), p.get('phaseStatus')) for p in build.get('phases', [])]!r}"
    )
    for field in ("startTime", "endTime"):
        assert field in build, (
            f"build {build_id} reports no {field}; the Duration bound is derived from the build's "
            f"own window and cannot be computed without it: {build!r}"
        )
    return build


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_on_role_propagation(ctx, call, *, description: str):
    """Retry ONLY CodeBuild's documented refusal of a not-yet-propagated role, with a raising bound."""
    from botocore.exceptions import ClientError

    budget_s = _budget_s(ctx, _ROLE_PROPAGATION_BUDGET_S)
    deadline = time.monotonic() + budget_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidInputException":
                raise
            last = exc
            time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded") from last
    raise AssertionError(
        f"{description} never succeeded within {budget_s:.0f}s; last refusal {last!r}"
    )


def _pair(a, b):
    return None if a is None or b is None else (a, b)


def _dimension_sets(cw, namespace: str, dim_name: str, dim_value: str) -> set[tuple[str, ...]]:
    seen: set[tuple[str, ...]] = set()
    token = None
    while True:
        kwargs: dict = {
            "Namespace": namespace,
            "Dimensions": [{"Name": dim_name, "Value": dim_value}],
        }
        if token:
            kwargs["NextToken"] = token
        page = cw.list_metrics(**kwargs)
        for m in page["Metrics"]:
            seen.add(tuple(sorted(d["Name"] for d in m["Dimensions"])))
        token = page.get("NextToken")
        if not token:
            return seen


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _poll_until_stable(probe, *, window_s, timeout_s, interval_s=20.0, description="reading",
                       ctx=None):
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if last is None:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} never held one complete value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
