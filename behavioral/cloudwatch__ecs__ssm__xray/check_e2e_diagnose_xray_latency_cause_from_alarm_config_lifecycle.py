"""e2e-diagnose-xray-latency-cause-from-alarm-config-lifecycle."""

from __future__ import annotations

import contextlib
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from behavioral_harness import tags

CHECK = "e2e-diagnose-xray-latency-cause-from-alarm-config-lifecycle"

#: A whole-scenario lifecycle that deploys the deployments/ sibling and destroys it before it
#: applies again.
GROUP = "deploy-e2e-lifecycle"

#: The task's SUBJECT services. cloudformation (the deploy front-end), lambda (the estate's log
#: generator, invoked exactly as the scenario does) and logs are infrastructure of the replay.
SERVICES = ["cloudwatch", "ecs", "ssm", "xray"]

#: The lifecycle has six phases: deploy, setup, pre_invoke, solve, cleanup, destroy.
PHASES = ("deploy", "setup", "pre_invoke", "solve", "cleanup", "destroy")

#: The longest single wait (a stack create or delete); a ceiling to FAIL at, never an asserted
#: latency.
_ROUND_DEADLINE_S = 600
#: A ceiling for the live publisher's frames to reflect a flag flip; never asserted as a latency.
_FLIP_DEADLINE_S = 180

_HERE = Path(__file__).parent
TEMPLATE = _HERE / "deployments" / "flint-xray-latency" / "template.json"

_THRESHOLD = 15000.0
_ALARM_PERIOD_S = 30          # high resolution; the scenario is 60 s x 3, kept at x 3 here
_BACKFILL_CADENCE_S = 12      # the scenario's backfill's cadence
_DEP_DIMS = [{"Name": "Service", "Value": "Quartz"}, {"Name": "Operation", "Value": "ReportPerson"}]
#: A frame already in flight when the publish flag flips can still land its dependency datum; the
#: absence window opens this long after the flip (the publisher reads the flag once per frame).
_FLIP_GRACE_S = 45


class _Trajectory:
    """The fixed solve: the reference script's reads, as SDK operations, in order.

    The argv below is for reference only and is
    executed by nobody (argv would also freeze the CLI's
    serialisation, and the jq/awk arithmetic is done in Python). One deliberate departure: the reference script
    takes `TraceSummaries[0]` of an UNFILTERED 3 h query, which in a shared account is whichever
    trace anyone wrote; the call sequence scopes the same query to the estate's minted service with
    `service("<name>")` and takes the newest summary.
    """

    OPS = (
        ("cloudwatch", "DescribeAlarms"),
        ("cloudwatch", "GetMetricStatistics"),
        ("xray", "GetTraceSummaries"),
        ("xray", "BatchGetTraces"),
    )
    UPSTREAM_ARGV = (
        "aws cloudwatch describe-alarms --alarm-names $ALARM_NAME --query MetricAlarms[0].[StateValue,"
        "Threshold,Statistic,ExtendedStatistic,MetricName,ComparisonOperator] --output text",
        "aws cloudwatch describe-alarms --alarm-names $ALARM_NAME --query "
        "MetricAlarms[0].Dimensions[?Name=='Operation'].Value | [0] --output text",
        "aws cloudwatch get-metric-statistics --namespace Flint --metric-name NonIdlePct --dimensions "
        "Name=Camera_name,Value=ALL Name=Operation,Value=CPU --start-time <-3h> --end-time <now> "
        "--period 3600 --statistics Average --query sort_by(Datapoints,&Timestamp)[-1].Average",
        "aws xray get-trace-summaries --start-time $START --end-time $END --no-paginate "
        "--query TraceSummaries[0].Id --output text",
        "aws xray batch-get-traces --trace-ids $TRACE_ID --query Traces[0].Segments[0].Document "
        "--output text",
    )


@tags("axis:happy-path", "concern:e2e", "concern:deploy", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """Replays the diagnose-latency-from-X-Ray task: deploy, seed, reset, diagnose, quiesce, destroy.

    The deployed p90 alarm echoes its 30 s x 3 configuration and its series tracks the flag; with
    the dependency metric off, the read-only solve attributes the breach to the QuartzAPI call.
    """
    assert not _cloudformation_unavailable(ctx), (
        "CloudFormation does not answer on this target; the lifecycle's deploy front-end is missing"
    )
    tok = ctx.unique_name("sim2real-flintx-")
    names = {
        "flint_ns": f"{tok}/Flint",
        "dep_ns": f"{tok}/Flint/Dependencies",
        "mode": f"/{tok}/flint/prod/quartz-latency-mode",
        "publish": f"/{tok}/flint/prod/publish-dependency-metrics",
        "trace_service": f"{tok}-FlintMotionDetection",
    }
    cw = ctx.client("cloudwatch")
    ecs = ctx.client("ecs")
    ssm = ctx.client("ssm")
    xr = ctx.client("xray")

    j = _Journal(PHASES)
    ctx.on_cleanup(j.dump)  # registered FIRST -> pops LAST -> prints even after a timeout
    side = _SideEffects(ctx, tok)
    ctx.on_cleanup(side.reap_net)  # before the deploy, so LIFO runs it AFTER the stack delete

    with j.phase("deploy"):
        est = _deploy_estate(ctx, tok, names)
        out = est["outputs"]
        want_out = {"ClusterName", "ServiceName", "TaskLogGroupName", "TaskDefinitionArn",
                    "QuartzLatencyModeParamName", "PublishDepMetricsParamName",
                    "QuartzBackfillFunctionName", "ServiceLatencyAlarmName", "TraceServiceName"}
        assert set(out) == want_out, f"stack outputs are {sorted(out)!r}, expected {sorted(want_out)!r}"
        assert out["TraceServiceName"] == names["trace_service"], (
            f"the trace service output {out['TraceServiceName']!r} is not the minted one"
        )
        alarm = _alarm(cw, out["ServiceLatencyAlarmName"])
        got = {k: alarm.get(k) for k in ("Namespace", "MetricName", "ExtendedStatistic", "Period",
                                          "EvaluationPeriods", "Threshold", "ComparisonOperator",
                                          "TreatMissingData")}
        want = {"Namespace": names["flint_ns"], "MetricName": "Time", "ExtendedStatistic": "p90",
                "Period": _ALARM_PERIOD_S, "EvaluationPeriods": 3, "Threshold": _THRESHOLD,
                "ComparisonOperator": "GreaterThanThreshold", "TreatMissingData": "notBreaching"}
        assert got == want, f"the deployed alarm reads {got!r}, the template declares {want!r}"
        flags = (_flag(ssm, names["mode"]), _flag(ssm, names["publish"]))
        assert flags == ("healthy", "true"), f"the deployed flags read {flags!r}"

    with j.phase("setup"):
        # the scenario's setup step, in its order.
        svc = _poll(lambda: _service(ecs, out), lambda s: s["runningCount"] >= s["desiredCount"] > 0,
                    timeout_s=300, description="the ECS service running its desired task")
        assert (svc["runningCount"], svc["desiredCount"]) == (1, 1), (
            f"the service runs {svc['runningCount']}/{svc['desiredCount']} tasks, expected 1/1"
        )
        # The publisher is live on BOTH sinks before anything is seeded: a trace for the minted
        # service is indexed, and its metrics are readable.
        traced = _poll(lambda: _summaries(xr, names["trace_service"], minutes=15), lambda s: s != [],
                       timeout_s=240, interval_s=10, description="the publisher's first frame trace")
        assert all(names["trace_service"] in {i["Name"] for i in t["ServiceIds"]} for t in traced), (
            f"a summary outside the minted service came back: {traced!r}"
        )
        inv = _invoke(ctx, out["QuartzBackfillFunctionName"], f"{tok}-backfill-dlq")
        assert inv["messagesProcessed"] == 0, f"the backfill Lambda answered {inv!r}"
        ssm.put_parameter(Name=names["mode"], Value="healthy", Overwrite=True)
        first = _backfill(cw, names, end=_backfill_end(est["applied_at"]), seed=1,
                          dependency=True)
        n_read = _poll(lambda: _sample_count(cw, names["dep_ns"], "APILatency", _DEP_DIMS,
                                             first["start"], first["end"]),
                       lambda n: n >= first["n"], timeout_s=180,
                       description=f"the {first['n']} backfilled dependency samples readable")
        assert n_read == first["n"], (
            f"setup backfilled {first['n']} dependency samples, the window holds {n_read}"
        )
        ssm.put_parameter(Name=names["mode"], Value="degraded", Overwrite=True)
        _await_newest_minute(cw, names, lambda lo, hi: lo > _THRESHOLD,
                             "the live alarmed series over the threshold on degraded latency")
        ssm.put_parameter(Name=names["mode"], Value="healthy", Overwrite=True)
        assert _flag(ssm, names["mode"]) == "healthy", "setup must leave the flag healthy"

    with j.phase("pre_invoke"):
        # the scenario's pre_invoke step, in its order: the X-Ray variant switches the
        # dependency metric OFF so the agent must reach for the traces.
        svc = _service(ecs, out)
        assert svc["runningCount"] == svc["desiredCount"] == 1, f"service {svc!r} is not 1/1"
        ssm.put_parameter(Name=names["publish"], Value="false", Overwrite=True)
        flipped_at = datetime.now(timezone.utc)
        ssm.put_parameter(Name=names["mode"], Value="healthy", Overwrite=True)
        second = _backfill(cw, names, end=_backfill_end(est["applied_at"]), seed=2,
                           dependency=False)
        # The reset backfills the Flint series again and deliberately NOT the dependency, over the
        # window setup already filled: Flint accumulates both, the dependency keeps setup's alone.
        lo, hi = max(first["start"], second["start"]), min(first["end"], second["end"])
        want_flint = _count_in(first["stamps"], lo, hi) + _count_in(second["stamps"], lo, hi)
        n_flint = _poll(lambda: _sample_count(cw, names["flint_ns"], "Time", _dims("ProcessFrame"),
                                              lo, hi),
                        lambda n: n >= want_flint, timeout_s=180,
                        description=f"{want_flint} accumulated Flint samples in the overlap")
        n_dep = _sample_count(cw, names["dep_ns"], "APILatency", _DEP_DIMS, lo, hi)
        assert (n_flint, n_dep) == (want_flint, _count_in(first["stamps"], lo, hi)), (
            f"over [{lo.isoformat()}, {hi.isoformat()}) the Flint series holds {n_flint} samples and "
            f"the dependency {n_dep}; the reset's backfill should add {_count_in(second['stamps'], lo, hi)} "
            f"to Flint ({want_flint}) and nothing to the dependency "
            f"({_count_in(first['stamps'], lo, hi)})"
        )
        _await_newest_minute(cw, names, lambda lo, hi: hi < _THRESHOLD,
                             "the live alarmed series back under the threshold on healthy latency")
        inv = _invoke(ctx, out["QuartzBackfillFunctionName"], f"{tok}-backfill-dlq")
        assert inv["messagesProcessed"] == 0, f"the backfill Lambda answered {inv!r}"
        ssm.put_parameter(Name=names["mode"], Value="degraded", Overwrite=True)
        _await_newest_minute(cw, names, lambda lo, hi: lo > _THRESHOLD,
                             "the live alarmed series over the threshold again for the agent")
        # The solve reads the newest trace, so a degraded frame's trace must be indexed first.
        _poll(lambda: _summaries(xr, names["trace_service"], minutes=15),
              lambda s: bool(s) and max(s, key=lambda t: t["StartTime"])["Duration"] > _THRESHOLD / 1000,
              timeout_s=_FLIP_DEADLINE_S, interval_s=10,
              description="the newest trace of the minted service carrying the degraded latency")
        # The suppression, as an ABSENCE behind a differential barrier: over the same window, opened
        # after the flip plus a frame's grace, the live publisher's Flint series DID receive (proof
        # it ran and published) while the dependency series received nothing.
        since = flipped_at + timedelta(seconds=_FLIP_GRACE_S)
        until = datetime.now(timezone.utc) + timedelta(minutes=1)
        live = _poll(lambda: _sample_count(cw, names["flint_ns"], "Time", _dims("FrameQuartzLag"),
                                           since, until),
                     lambda n: n >= 5, timeout_s=180, interval_s=10,
                     description="the live publisher's frames since the flip readable")
        dep_live = _sample_count(cw, names["dep_ns"], "APILatency", _DEP_DIMS, since, until)
        assert live >= 5, (
            f"the live publisher should have landed frames since the flip; FrameQuartzLag holds {live}"
        )
        assert dep_live == 0, (
            f"publish-dependency-metrics=false should stop the dependency metric, yet it received "
            f"{dep_live} samples since {since.isoformat()} while FrameQuartzLag received {live}"
        )

    with j.phase("solve"):
        answer, fired_ops = _solve(ctx, out["ServiceLatencyAlarmName"], names)
        # the frozen sequence is GRADED -- sufficient, and nothing outside it needed.
        assert fired_ops == _Trajectory.OPS, (
            f"the trajectory fired {fired_ops!r}, the frozen sequence is {_Trajectory.OPS!r}"
        )
        a = answer["alarm"]
        assert (a["stat"], a["MetricName"], a["Threshold"], a["ComparisonOperator"],
                a["operation"]) == ("p90", "Time", _THRESHOLD, "GreaterThanThreshold",
                                    "FrameQuartzLag"), f"the alarm the agent reads is {a!r}"
        assert 44.0 <= answer["cpu"] <= 52.0, (
            f"the latest hourly CPU average should sit in the healthy 44-52 % band, got {answer['cpu']!r}"
        )
        t = answer["trace"]
        assert t["service"] == names["trace_service"], f"the trace's root segment is {t['service']!r}"
        assert abs((t["internal_ms"] + t["quartz_ms"]) - t["total_ms"]) <= 5, (
            f"the two subsegments ({t['internal_ms']} + {t['quartz_ms']} ms) should tile the root's "
            f"{t['total_ms']} ms"
        )
        assert t["quartz_ms"] > _THRESHOLD > t["internal_ms"], (
            f"the QuartzAPI subsegment ({t['quartz_ms']} ms) alone should exceed the {_THRESHOLD} ms "
            f"threshold and the InternalPipeline one ({t['internal_ms']} ms) should not"
        )
        assert t["quartz_pct"] > 50, (
            f"the downstream call should be the majority of the trace, it is {t['quartz_pct']}%"
        )
        path = t["root_cause_path"]
        assert [e["Name"] for e in path] == [names["trace_service"], "QuartzAPI"], (
            f"X-Ray's response-time root cause should run service -> QuartzAPI, it reads {path!r}"
        )

    with j.phase("cleanup"):
        # Quiesce the live publisher before destroy.
        ecs.update_service(cluster=out["ClusterName"], service=out["ServiceName"], desiredCount=0)
        drained = _poll(lambda: (_service(ecs, out)["runningCount"],
                                 _running_tasks(ecs, out["ClusterName"])),
                        lambda r: r == (0, []), timeout_s=300, interval_s=5,
                        description="the service draining to zero running tasks")
        assert drained == (0, []), f"the service still runs tasks: {drained!r}"

    with j.phase("destroy"):
        assert est["destroy"]() == 0, "stack deletion did not reach DELETE_COMPLETE"
        err = _absent_error(lambda: ctx.client("cloudformation").describe_stack_resources(
            StackName=est["stack"]))
        expected = ("ValidationError", f"Stack with id {est['stack']} does not exist")
        assert err == expected, (
            f"CloudFormation still describes resources of the deleted stack {est['stack']!r}: "
            f"expected {expected!r}, got {err!r} -- the delete did not release them"
        )
        assert est["destroy"]() == 0, "a second destroy must be a clean no-op"
        # What the stack does NOT own: the log group Container Insights creates for the cluster,
        # and, as a guard, any task definition revision the delete left INACTIVE.
        left = side.reap()
        assert left == {"insights_log_group": [], "inactive_revisions": []}, (
            f"side effects the stack delete does not release are still present: {left!r}"
        )


# ===== the fixed call sequence, replayed =====
def _solve(ctx, alarm_name: str, names: dict) -> tuple[dict, tuple]:
    """Replay _Trajectory and return (what it found, the ops it fired), for run() to grade."""
    cw = ctx.client("cloudwatch")
    xr = ctx.client("xray")
    fired: list[tuple[str, str]] = []

    def op(service, name):
        if (service, name) not in fired:
            fired.append((service, name))

    op("cloudwatch", "DescribeAlarms")
    raw = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    alarm = {k: raw.get(k) for k in ("StateValue", "MetricName", "Threshold", "ComparisonOperator")}
    alarm["stat"] = raw.get("ExtendedStatistic") or raw.get("Statistic")
    op("cloudwatch", "DescribeAlarms")
    raw = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    alarm["operation"] = next((d["Value"] for d in raw["Dimensions"] if d["Name"] == "Operation"), None)

    end = datetime.now(timezone.utc)
    op("cloudwatch", "GetMetricStatistics")
    pts = cw.get_metric_statistics(Namespace=names["flint_ns"], MetricName="NonIdlePct",
                                   Dimensions=_dims("CPU"), StartTime=end - timedelta(hours=3),
                                   EndTime=end, Period=3600, Statistics=["Average"])["Datapoints"]
    assert pts, "the CPU series has no hourly datapoints over the last 3 h"
    cpu = sorted(pts, key=lambda p: p["Timestamp"])[-1]["Average"]

    op("xray", "GetTraceSummaries")
    summaries = _summaries(xr, names["trace_service"], minutes=180)
    assert summaries, f"no trace summaries for {names['trace_service']!r} over the last 3 h"
    newest = max(summaries, key=lambda s: s["StartTime"])
    op("xray", "BatchGetTraces")
    traces = xr.batch_get_traces(TraceIds=[newest["Id"]])["Traces"]
    assert len(traces) == 1 and len(traces[0]["Segments"]) == 1, (
        f"BatchGetTraces({newest['Id']!r}) returned {traces!r}"
    )
    doc = json.loads(traces[0]["Segments"][0]["Document"])
    subs = {s["name"]: s for s in _walk(doc) if s is not doc}
    assert sorted(subs) == ["InternalPipeline", "QuartzAPI"], f"subsegments read {sorted(subs)!r}"

    def ms(seg):
        return int((seg["end_time"] - seg["start_time"]) * 1000)

    total = ms(doc)
    causes = newest.get("ResponseTimeRootCauses") or []
    path = causes[0]["Services"][0]["EntityPath"] if causes and causes[0].get("Services") else []
    trace = {"service": doc["name"], "quartz_ms": ms(subs["QuartzAPI"]),
             "internal_ms": ms(subs["InternalPipeline"]), "total_ms": total,
             "quartz_pct": round(ms(subs["QuartzAPI"]) * 100 / total) if total else 0,
             "root_cause_path": path}
    return {"alarm": alarm, "cpu": cpu, "trace": trace}, tuple(fired)


def _walk(seg: dict):
    """Every segment object in the document, depth first -- jq's `.. | objects | select(.name)`."""
    yield seg
    for sub in seg.get("subsegments") or []:
        yield from _walk(sub)


def _summaries(xr, service: str, *, minutes: int) -> list[dict]:
    now = datetime.now(timezone.utc)
    kw = {"StartTime": now - timedelta(minutes=minutes), "EndTime": now + timedelta(minutes=1),
          "FilterExpression": f'service("{service}")'}
    out = []
    while True:
        page = xr.get_trace_summaries(**kw)
        out.extend(page.get("TraceSummaries", []))
        if not page.get("NextToken"):
            return out
        kw["NextToken"] = page["NextToken"]


class _SideEffects:
    """Reap what the stack's delete does not own; ONE idempotent-by-state function, two call sites
    (graded in destroy, and the never-raising on_cleanup net)."""

    def __init__(self, ctx, tok: str) -> None:
        self.ctx, self.result = ctx, None
        self.group = f"/aws/ecs/containerinsights/{tok}-cluster/performance"
        self.family = f"{tok}-flint-motion-detection-task"

    def _groups(self) -> list[str]:
        out = []
        for page in self.ctx.client("logs").get_paginator("describe_log_groups").paginate(
                logGroupNamePrefix=self.group):
            out.extend(g["logGroupName"] for g in page.get("logGroups", [])
                       if g["logGroupName"] == self.group)
        return out

    def _inactive(self) -> list[str]:
        out = []
        for page in self.ctx.client("ecs").get_paginator("list_task_definitions").paginate(
                familyPrefix=self.family, status="INACTIVE"):
            out.extend(page.get("taskDefinitionArns", []))
        return out

    def reap(self) -> dict:
        if self.result is not None:
            return self.result
        from botocore.exceptions import ClientError

        logs, ecs = self.ctx.client("logs"), self.ctx.client("ecs")
        # A late metrics flush can recreate the group, so this is a bounded LOOP of rounds.
        deadline = time.monotonic() + 90
        while True:
            for g in self._groups():
                try:
                    logs.delete_log_group(logGroupName=g)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            arns = self._inactive()
            for i in range(0, len(arns), 10):
                ecs.delete_task_definitions(taskDefinitions=arns[i:i + 10])
            left = {"insights_log_group": self._groups(), "inactive_revisions": self._inactive()}
            if left == {"insights_log_group": [], "inactive_revisions": []} \
                    or time.monotonic() >= deadline:
                self.result = left
                return left
            time.sleep(10)

    def reap_net(self) -> None:
        try:
            left = self.reap()
        except Exception as exc:  # noqa: BLE001 - a teardown must not mask the verdict
            raise RuntimeError(
                f"{self.group} / {self.family}: {type(exc).__name__}: {exc}"
            ) from exc
        if any(left.values()):
            raise RuntimeError(f"still present after reap: {left!r}")


class _PhaseError(Exception):
    """A non-assertion failure, re-raised with its phase named and its own message preserved."""


class _Journal:
    """Phase attribution for an engine that records ONE verdict per check (see the lifecycle
    reference): an AssertionError stays one, anything else keeps its original text."""

    def __init__(self, phases: tuple[str, ...]) -> None:
        self.phases, self.log, self.cur = phases, [], None

    @contextlib.contextmanager
    def phase(self, name: str):
        i, t0 = self.phases.index(name) + 1, time.monotonic()
        self.cur = name
        print(f"  [phase {i}/{len(self.phases)} {name}]", flush=True)
        try:
            yield
        except AssertionError as exc:
            self._note(name, i, t0, "MISMATCH")
            raise AssertionError(f"[phase {i}/{len(self.phases)} {name}] {exc}") from exc
        except Exception as exc:
            self._note(name, i, t0, "ERROR")
            raise _PhaseError(
                f"[phase {i}/{len(self.phases)} {name}] {type(exc).__name__}: {exc}"
            ) from exc
        self._note(name, i, t0, "PASS")

    def _note(self, name: str, i: int, t0: float, verdict: str) -> None:
        self.log.append((name, i, round((time.monotonic() - t0) * 1000, 1), verdict))

    def dump(self) -> None:
        print("  [phases] " + " ".join(f"{i}:{n}={v}/{ms:.0f}ms" for n, i, ms, v in self.log),
              flush=True)
        if len(self.log) < len(self.phases):
            print(f"  [phases] DEPTH_REACHED={len(self.log)}/{len(self.phases)} "
                  f"(stopped in {self.cur!r})", flush=True)


def _poll(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _absent_error(fn) -> tuple:
    """The (error code, message) fn() raises; a success fails the check -- for asserting an ABSENCE."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


def _cloudformation_unavailable(ctx) -> bool:
    from botocore.exceptions import ClientError

    try:
        ctx.client("cloudformation").list_stacks(StackStatusFilter=["CREATE_COMPLETE"])
    except ClientError:
        return False
    except Exception:  # noqa: BLE001 - only "does not answer at all" counts
        return True
    return False


def _dims(operation: str) -> list[dict]:
    return [{"Name": "Camera_name", "Value": "ALL"}, {"Name": "Operation", "Value": operation}]


def _alarm(cw, name: str) -> dict:
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(found) == 1, f"alarm {name!r} should be described exactly once, got {found!r}"
    return found[0]


def _await_newest_minute(cw, names: dict, predicate, description: str) -> tuple[float, float]:
    """Poll the alarmed series until its newest 60 s bucket's (Minimum, Maximum) satisfy predicate."""
    def newest():
        end = datetime.now(timezone.utc)
        pts = cw.get_metric_statistics(Namespace=names["flint_ns"], MetricName="Time",
                                       Dimensions=_dims("FrameQuartzLag"),
                                       StartTime=end - timedelta(minutes=5), EndTime=end, Period=60,
                                       Statistics=["Minimum", "Maximum"])["Datapoints"]
        if not pts:
            return None
        last = max(pts, key=lambda p: p["Timestamp"])
        return last["Minimum"], last["Maximum"]

    return _poll(newest, lambda b: b is not None and predicate(*b), timeout_s=_FLIP_DEADLINE_S,
                 interval_s=5, description=description)


def _flag(ssm, name: str) -> str:
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _service(ecs, out: dict) -> dict:
    found = ecs.describe_services(cluster=out["ClusterName"], services=[out["ServiceName"]])
    assert len(found["services"]) == 1, f"DescribeServices returned {found!r}"
    return found["services"][0]


def _running_tasks(ecs, cluster: str) -> list[str]:
    arns = []
    for page in ecs.get_paginator("list_tasks").paginate(cluster=cluster, desiredStatus="RUNNING"):
        arns.extend(page.get("taskArns", []))
    if not arns:
        return []
    return [t["taskArn"] for t in ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
            if t["lastStatus"] != "STOPPED"]


def _log_streams(ctx, group: str) -> list[str]:
    out = []
    for page in ctx.client("logs").get_paginator("describe_log_streams").paginate(logGroupName=group):
        out.extend(s["logStreamName"] for s in page.get("logStreams", []))
    return out


def _invoke(ctx, function: str, queue: str) -> dict:
    """Invoke the backfill Lambda as the scenario does, with a BOUNDED retry for the two documented
    propagation refusals (a Pending function, a not-yet-assumable role); read FunctionError."""
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = lam.invoke(FunctionName=function, InvocationType="RequestResponse",
                              Payload=json.dumps({"isPulling": "True", "queueName": queue}).encode())
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceConflictException",
                                                     "AccessDeniedException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    payload = json.loads(resp["Payload"].read())
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"the backfill Lambda failed: {resp.get('FunctionError')!r} {payload!r}"
    )
    assert payload.get("statusCode") == 200, f"the backfill Lambda answered {payload!r}"
    return json.loads(payload["body"])


def _backfill_end(applied_at: datetime) -> datetime:
    """The scenario's backfill ends 5 min before now; it also must end before the live task could
    have published anything, so the window it fills is the backfill's alone."""
    end = min(datetime.now(timezone.utc) - timedelta(minutes=5), applied_at - timedelta(minutes=1))
    return end.replace(second=0, microsecond=0)


def _backfill(cw, names: dict, *, end: datetime, seed: int, dependency: bool) -> dict:
    """the scenario's backfill_healthy_history: ~3 h of healthy samples every ~12 s, all six Flint
    series plus -- in setup's version only, `dependency=True` -- the dependency, in batches of
    1000. The X-Ray pre_invoke's version skips the dependency on purpose. Seeded, so the sample
    count is known.

    The window starts 2 h 50 min back, not the scenario's 3 h: measured, samples whose timestamp is
    already ~3 h old when PutMetricData accepts them are not served by GetMetricStatistics (a
    backfill of 874 samples read back 868, the missing six all in its oldest minute), so a
    window touching the 3 h edge makes the readback count a race against the clock."""
    rnd = random.Random(seed)
    start = (datetime.now(timezone.utc) - timedelta(hours=2, minutes=50)).replace(
        second=0, microsecond=0)
    flint, deps, stamps = [], [], []
    ts = start
    while ts < end:
        pf, motion, hls = rnd.uniform(450, 750), rnd.uniform(1.5, 1.7), rnd.uniform(950, 1100)
        internal = pf + motion + hls
        quartz = rnd.uniform(2000, 4500)
        for name, value, operation, unit in (
                ("Time", pf, "ProcessFrame", "Milliseconds"),
                ("Time", motion, "MotionDetection", "Milliseconds"),
                ("Time", hls, "HLSStartLag", "Milliseconds"),
                ("Time", internal, "InternalPipelineTime", "Milliseconds"),
                ("Time", internal + quartz, "FrameQuartzLag", "Milliseconds"),
                ("NonIdlePct", rnd.uniform(44.0, 52.0), "CPU", "Percent")):
            flint.append({"MetricName": name, "Dimensions": _dims(operation), "Value": value,
                          "Unit": unit, "Timestamp": ts})
        deps.append({"MetricName": "APILatency", "Dimensions": _DEP_DIMS, "Value": quartz,
                     "Unit": "Milliseconds", "Timestamp": ts})
        stamps.append(ts)
        ts += timedelta(seconds=_BACKFILL_CADENCE_S + rnd.uniform(-1, 1))
    for ns, batch in ((names["flint_ns"], flint), (names["dep_ns"], deps if dependency else [])):
        for i in range(0, len(batch), 1000):
            cw.put_metric_data(Namespace=ns, MetricData=batch[i:i + 1000])
    return {"start": start, "end": end, "n": len(stamps), "stamps": stamps}


def _count_in(stamps, lo: datetime, hi: datetime) -> int:
    return sum(1 for t in stamps if lo <= t < hi)


def _sample_count(cw, namespace: str, metric: str, dims: list, lo: datetime, hi: datetime) -> int:
    pts = cw.get_metric_statistics(Namespace=namespace, MetricName=metric, Dimensions=dims,
                                   StartTime=lo, EndTime=hi, Period=3600,
                                   Statistics=["SampleCount"])["Datapoints"]
    return int(sum(p["SampleCount"] for p in pts))


def _stack_status(ctx, stack: str) -> str:
    from botocore.exceptions import ClientError

    try:
        stacks = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise
    return stacks[0]["StackStatus"]


def _deploy_estate(ctx, tok: str, names: dict) -> dict:
    """Apply the template; register the delete BEFORE the create; return outputs."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "the account has no shared network VPC -- a prerequisite every account guarantees"
    vpc = vpcs[0]["VpcId"]
    subnets = sorted(s["SubnetId"] for s in ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"])
    assert subnets, f"shared network {vpc!r} has no network subnets"
    stack = tok
    state = {"deleted": None}

    def _delete() -> int:
        """Idempotent-once by STATE, so the net below stays a real destroy."""
        if state["deleted"] is not None:
            return state["deleted"]
        cfn.delete_stack(StackName=stack)
        try:
            _poll(lambda: _stack_status(ctx, stack), lambda s: s in ("GONE", "DELETE_FAILED"),
                  timeout_s=_ROUND_DEADLINE_S, interval_s=10, description=f"stack {stack} deleted")
        except AssertionError:
            state["deleted"] = 1
            return 1
        state["deleted"] = 0 if _stack_status(ctx, stack) == "GONE" else 1
        return state["deleted"]

    def _delete_net() -> None:
        try:
            rc = _delete()
        except Exception as exc:  # noqa: BLE001 - a teardown must not mask the verdict
            teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if (
                not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
            ):
                raise RuntimeError(
                    f"stack {stack} delete raised {type(exc).__name__}: {exc}"
                ) from exc
            return
        if rc != 0:
            raise RuntimeError(f"stack {stack} did not reach DELETE_COMPLETE")

    ctx.on_cleanup(_delete_net)  # BEFORE the create: a check killed mid-apply otherwise strands it
    applied_at = datetime.now(timezone.utc)
    params = {"Token": tok, "VpcId": vpc, "SubnetIds": ",".join(subnets),
              "FlintNamespace": names["flint_ns"], "DependencyNamespace": names["dep_ns"],
              "LatencyModeParamName": names["mode"], "PublishDepMetricsParamName": names["publish"],
              "TraceServiceName": names["trace_service"],
              "AlarmPeriod": str(_ALARM_PERIOD_S)}
    cfn.create_stack(StackName=stack, TemplateBody=TEMPLATE.read_text(),
                     Capabilities=["CAPABILITY_IAM"],
                     Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
                     Tags=[{"Key": "sim2real", "Value": "api-and-observability"}])
    status = _poll(lambda: _stack_status(ctx, stack),
                   lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE",
                                   "ROLLBACK_FAILED", "GONE"),
                   timeout_s=_ROUND_DEADLINE_S, interval_s=10,
                   description=f"stack {stack} reaching a terminal state")
    if status != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
                  if e["ResourceStatus"].endswith("FAILED")][:5]
        raise AssertionError(f"stack {stack} reached {status!r}; failed resources {failed!r}")
    outs = {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    return {"stack": stack, "outputs": outs, "destroy": _delete, "applied_at": applied_at}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
