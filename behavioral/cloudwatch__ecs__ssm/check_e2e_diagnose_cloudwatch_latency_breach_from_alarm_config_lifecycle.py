"""e2e-diagnose-cloudwatch-latency-breach-from-alarm-config-lifecycle."""

from __future__ import annotations

import contextlib
import json
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from behavioral_harness import tags

CHECK = "e2e-diagnose-cloudwatch-latency-breach-from-alarm-config-lifecycle"

#: A whole-task lifecycle: deploy the estate from its deployments/ template, run the task, destroy.
GROUP = "deploy-e2e-lifecycle"

#: The task's SUBJECT services. cloudformation (the deploy front-end), lambda (the estate's log
#: generator) and logs are infrastructure of the replay, not what is under test.
SERVICES = ["cloudwatch", "ecs", "ssm"]

#: The reference lifecycle has its own setup step and a pre-solve reset but no
#: post-solve hook, so the lifecycle is SIX phases.
PHASES = ("deploy", "setup", "pre_invoke", "solve", "cleanup", "destroy")

#: The longest single wait (a stack create or delete); a ceiling to FAIL at, never an asserted
#: latency.
_ROUND_DEADLINE_S = 600
#: A ceiling for the live publisher's frames to reflect a flag flip; never asserted as a latency.
_FLIP_DEADLINE_S = 180

_HERE = Path(__file__).parent
TEMPLATE = _HERE / "deployments" / "flint-latency" / "template.json"

_THRESHOLD = 15000.0
_ALARM_PERIOD_S = 30          # high resolution, over 3 evaluation periods
_BACKFILL_CADENCE_S = 12      # the backfill's cadence
_COMPONENTS = ("FrameQuartzLag", "ProcessFrame", "MotionDetection", "HLSStartLag",
               "InternalPipelineTime")
_INTERNAL = ("ProcessFrame", "MotionDetection", "HLSStartLag", "InternalPipelineTime")
_DEP_DIMS = [{"Name": "Service", "Value": "Quartz"}, {"Name": "Operation", "Value": "ReportPerson"}]


class _Trajectory:
    """The reference diagnosis's reads, as SDK operations, in order.

    The argv below is provenance only and is executed by nobody (argv would also freeze the
    CLI's serialisation). Two deliberate departures from the reference, both recorded here so
    they are not silent:
      * the reference discovers the dependency's dimensions with `list-metrics`. Metric DISCOVERY
        lags readability by minutes, so a fixed read sequence that gates on it false-fails a
        faithful target; the dimensions are taken from the estate's own declaration instead.
      * the reference reads the latest Period=300 average. A 5-minute bucket straddles the
        degraded flip, so its average can sit under the threshold while the alarm is correctly
        firing; the trajectory reads Period=60 and keeps the latest bucket.
    """

    OPS = (
        ("cloudwatch", "DescribeAlarms"),
        ("cloudwatch", "GetMetricStatistics"),
        ("cloudformation", "DescribeStacks"),
        ("ecs", "DescribeServices"),
        ("ssm", "GetParametersByPath"),
        ("ssm", "GetParameter"),
    )
    UPSTREAM_ARGV = (
        "aws cloudwatch describe-alarms --alarm-names $ALARM_NAME --query MetricAlarms[0].[StateValue,"
        "Namespace,MetricName,ExtendedStatistic,Threshold,ComparisonOperator,EvaluationPeriods,Period]",
        "aws cloudwatch get-metric-statistics --namespace $NAMESPACE --metric-name $METRIC "
        "--dimensions Name=Camera_name,Value=ALL Name=Operation,Value=<op> --period 300 --statistics Average",
        "aws cloudwatch list-metrics --namespace <deps> --metric-name APILatency",
        "aws cloudformation describe-stacks --stack-name <stack> --query Stacks[0].Outputs",
        "aws ecs describe-services --cluster $CLUSTER --services $SERVICE",
        "aws ssm get-parameters-by-path --path <root> --recursive --query Parameters[?contains(Name,'latency-mode')]",
        "aws ssm get-parameter --name $LATENCY_PARAM",
    )


@tags("axis:happy-path", "concern:e2e", "concern:deploy", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """The latency-breach lifecycle: deploy, seed, reset, diagnose, quiesce, destroy.

    The deployed p90 alarm echoes its 30 s x 3 configuration, the live series tracks an SSM flag
    over its threshold and back, and the read-only trajectory pins the breach on the dependency.
    """
    assert not _cloudformation_unavailable(ctx), (
        "CloudFormation does not answer on this target; the lifecycle's deploy front-end is missing"
    )
    tok = ctx.unique_name("sim2real-flint-")
    names = {
        "flint_ns": f"{tok}/Flint",
        "dep_ns": f"{tok}/Flint/Dependencies",
        "mode": f"/{tok}/flint/prod/quartz-latency-mode",
        "publish": f"/{tok}/flint/prod/publish-dependency-metrics",
    }
    cw = ctx.client("cloudwatch")
    ecs = ctx.client("ecs")
    ssm = ctx.client("ssm")

    j = _Journal(PHASES)
    ctx.on_cleanup(j.dump)  # registered FIRST -> pops LAST -> prints even after a timeout
    side = _SideEffects(ctx, tok)
    ctx.on_cleanup(side.reap_net)  # before the deploy, so LIFO runs it AFTER the stack delete

    with j.phase("deploy"):
        est = _deploy_estate(ctx, tok, names)
        out = est["outputs"]
        want_out = {"ClusterName", "ServiceName", "TaskLogGroupName", "TaskDefinitionArn",
                    "QuartzLatencyModeParamName", "PublishDepMetricsParamName",
                    "QuartzBackfillFunctionName", "ServiceLatencyAlarmName"}
        assert set(out) == want_out, f"stack outputs are {sorted(out)!r}, expected {sorted(want_out)!r}"
        assert (out["QuartzLatencyModeParamName"], out["PublishDepMetricsParamName"]) == (
            names["mode"], names["publish"]), f"flag outputs {out!r} do not name the minted flags"
        alarm = _alarm(cw, out["ServiceLatencyAlarmName"])
        got = {k: alarm.get(k) for k in ("Namespace", "MetricName", "ExtendedStatistic", "Period",
                                          "EvaluationPeriods", "Threshold", "ComparisonOperator",
                                          "TreatMissingData", "Unit")}
        want = {"Namespace": names["flint_ns"], "MetricName": "Time", "ExtendedStatistic": "p90",
                "Period": _ALARM_PERIOD_S, "EvaluationPeriods": 3, "Threshold": _THRESHOLD,
                "ComparisonOperator": "GreaterThanThreshold", "TreatMissingData": "notBreaching",
                "Unit": "Milliseconds"}
        assert got == want, f"the deployed alarm reads {got!r}, the template declares {want!r}"
        flags = (_flag(ssm, names["mode"]), _flag(ssm, names["publish"]))
        assert flags == ("healthy", "true"), f"the deployed flags read {flags!r}"

    with j.phase("setup"):
        # The reference setup step, in its order.
        svc = _poll(lambda: _service(ecs, out), lambda s: s["runningCount"] >= s["desiredCount"] > 0,
                    timeout_s=300, description="the ECS service running its desired task")
        assert (svc["runningCount"], svc["desiredCount"]) == (1, 1), (
            f"the service runs {svc['runningCount']}/{svc['desiredCount']} tasks, expected 1/1"
        )
        streams = _poll(lambda: _log_streams(ctx, out["TaskLogGroupName"]), lambda s: s != [],
                        timeout_s=180, description="the container's first log stream")
        assert all(s.startswith("HLSProcess/container/HLSProcess/") for s in streams), (
            f"container logs should route under the declared prefix, streams are {streams!r}"
        )
        inv = _invoke(ctx, out["QuartzBackfillFunctionName"], f"{tok}-backfill-dlq")
        assert inv["messagesProcessed"] == 0, f"the backfill Lambda answered {inv!r}"
        ssm.put_parameter(Name=names["mode"], Value="healthy", Overwrite=True)
        first = _backfill(cw, names, end=_backfill_end(est["applied_at"]), seed=1)
        n_read = _poll(lambda: _sample_count(cw, names["flint_ns"], "ProcessFrame",
                                             first["start"], first["end"]),
                       lambda n: n >= first["n"], timeout_s=180,
                       description=f"the {first['n']} backfilled ProcessFrame samples readable")
        assert n_read == first["n"], (
            f"the backfill wrote {first['n']} ProcessFrame samples, the window holds {n_read}"
        )
        ssm.put_parameter(Name=names["mode"], Value="degraded", Overwrite=True)
        _await_newest_minute(cw, names, lambda lo, hi: lo > _THRESHOLD,
                             "the live alarmed series over the threshold on degraded latency")
        ssm.put_parameter(Name=names["mode"], Value="healthy", Overwrite=True)
        assert _flag(ssm, names["mode"]) == "healthy", "setup must leave the flag healthy"

    with j.phase("pre_invoke"):
        # The reference pre-solve reset, in its order.
        svc = _service(ecs, out)
        assert svc["runningCount"] == svc["desiredCount"] == 1, f"service {svc!r} is not 1/1"
        ssm.put_parameter(Name=names["publish"], Value="true", Overwrite=True)
        ssm.put_parameter(Name=names["mode"], Value="healthy", Overwrite=True)
        second = _backfill(cw, names, end=_backfill_end(est["applied_at"]), seed=2)
        # The per-trial reset re-backfills over the same window: PutMetricData accumulates.
        lo, hi = max(first["start"], second["start"]), min(first["end"], second["end"])
        want_n = _count_in(first["stamps"], lo, hi) + _count_in(second["stamps"], lo, hi)
        n_read = _poll(lambda: _sample_count(cw, names["flint_ns"], "ProcessFrame", lo, hi),
                       lambda n: n >= want_n, timeout_s=180,
                       description=f"{want_n} accumulated samples in the overlapping window")
        assert n_read == want_n, (
            f"two backfills put {want_n} samples in [{lo.isoformat()}, {hi.isoformat()}), the "
            f"window holds {n_read} -- the reset must accumulate, not replace"
        )
        _await_newest_minute(cw, names, lambda lo, hi: hi < _THRESHOLD,
                             "the live alarmed series back under the threshold on healthy latency")
        inv = _invoke(ctx, out["QuartzBackfillFunctionName"], f"{tok}-backfill-dlq")
        assert inv["messagesProcessed"] == 0, f"the backfill Lambda answered {inv!r}"
        ssm.put_parameter(Name=names["mode"], Value="degraded", Overwrite=True)
        # Two consecutive degraded minutes: the older one is complete, so the solve's newest
        # minute holding the same frames in all three series is a degraded one, not the flip's.
        _await_newest_minute(cw, names, lambda lo, hi: lo > _THRESHOLD,
                             "two consecutive minutes of the live alarmed series over the "
                             "threshold for the agent", minutes=2,
                             timeout_s=_FLIP_DEADLINE_S + 60)

    with j.phase("solve"):
        answer, fired_ops = _solve(ctx, est["stack"], out["ServiceLatencyAlarmName"],
                                   "/" + tok + "/flint/prod")
        # The frozen sequence is GRADED -- sufficient, and nothing outside it needed.
        assert fired_ops == _Trajectory.OPS, (
            f"the trajectory fired {fired_ops!r}, the frozen sequence is {_Trajectory.OPS!r}"
        )
        a = answer["alarm"]
        assert (a["ExtendedStatistic"], a["MetricName"], a["Threshold"], a["EvaluationPeriods"],
                a["Period"], a["ComparisonOperator"], a["tracked_op"]) == (
            "p90", "Time", _THRESHOLD, 3, _ALARM_PERIOD_S, "GreaterThanThreshold",
            "FrameQuartzLag"), (
            f"the alarm the agent reads is {a!r}"
        )
        latest = answer["latest"]
        assert sorted(latest) == sorted(_COMPONENTS + ("CPU", "APILatency")), (
            f"the trajectory read {sorted(latest)!r}"
        )
        internal = {op: latest[op] for op in _INTERNAL}
        assert all(v < _THRESHOLD for v in internal.values()), (
            f"every internal component should sit under {_THRESHOLD}: {internal!r}"
        )
        assert latest["APILatency"] > _THRESHOLD and latest["FrameQuartzLag"] > _THRESHOLD, (
            f"the dependency ({latest['APILatency']!r}) and the end-to-end lag "
            f"({latest['FrameQuartzLag']!r}) should both be over {_THRESHOLD}"
        )
        # The decomposition, in the newest minute where all three series hold the same frames:
        # end-to-end minus internal IS the dependency, so the dependency explains the breach.
        e2e, internal_t, dep = answer["aligned"]
        assert abs((e2e - internal_t) - dep) < 1.0, (
            f"end-to-end ({e2e!r}) minus internal ({internal_t!r}) should equal the dependency's "
            f"latency ({dep!r}) over the same frames: the breach is the dependency"
        )
        assert dep > _THRESHOLD > internal_t, (
            f"over those frames the dependency ({dep!r}) alone should exceed {_THRESHOLD} and the "
            f"internal pipeline ({internal_t!r}) should not"
        )
        assert 0.0 < latest["CPU"] < 100.0, f"CPU reads {latest['CPU']!r}"
        assert (answer["running"], answer["desired"]) == (1, 1), (
            f"the service should run its desired task: {answer['running']}/{answer['desired']}"
        )
        assert answer["flag"] == (names["mode"], "degraded"), (
            f"the root cause is the latency-mode flag set to degraded, the agent found {answer['flag']!r}"
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
        got = _absent_error(lambda: ctx.client("cloudformation").describe_stack_resources(
            StackName=est["stack"]))
        assert got == ("ValidationError", f"Stack with id {est['stack']} does not exist"), (
            f"CloudFormation still describes resources of the deleted stack {est['stack']!r} "
            f"(got {got!r}) -- the delete did not release them"
        )
        assert est["destroy"]() == 0, "a second destroy must be a clean no-op"
        # What the stack does NOT own: the log group Container Insights creates for the cluster
        # (measured: it survives DELETE_COMPLETE, on every run) -- and, as a guard, any task
        # definition revision the delete left INACTIVE rather than deleted (measured: none).
        left = side.reap()
        assert left == {"insights_log_group": [], "inactive_revisions": []}, (
            f"side effects the stack delete does not release are still present: {left!r}"
        )


# ===== the reference reads, replayed =====
def _solve(ctx, stack: str, alarm_name: str, flag_root: str) -> tuple[dict, tuple]:
    """Replay _Trajectory and return (what it found, the ops it fired), for run() to grade."""
    cw = ctx.client("cloudwatch")
    ssm = ctx.client("ssm")
    fired: list[tuple[str, str]] = []

    def op(service, name):
        if (service, name) not in fired:
            fired.append((service, name))

    op("cloudwatch", "DescribeAlarms")
    raw = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    alarm = {k: raw.get(k) for k in ("StateValue", "Namespace", "MetricName", "ExtendedStatistic",
                                      "Threshold", "ComparisonOperator", "EvaluationPeriods",
                                      "Period")}
    alarm["tracked_op"] = next(d["Value"] for d in raw["Dimensions"] if d["Name"] == "Operation")

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=3)

    def series(namespace, metric, dims):
        op("cloudwatch", "GetMetricStatistics")
        pts = cw.get_metric_statistics(Namespace=namespace, MetricName=metric, Dimensions=dims,
                                       StartTime=start, EndTime=end, Period=60,
                                       Statistics=["Average", "SampleCount"])["Datapoints"]
        assert pts, f"{namespace}/{metric} {dims!r} has no datapoints in the last 3 h"
        return {p["Timestamp"]: (p["Average"], p["SampleCount"]) for p in pts}

    ns = alarm["Namespace"]
    got = {o: series(ns, alarm["MetricName"], _dims(o)) for o in _COMPONENTS}
    got["CPU"] = series(ns, "NonIdlePct", _dims("CPU"))
    got["APILatency"] = series(ns + "/Dependencies", "APILatency", _DEP_DIMS)
    found = {k: v[max(v)][0] for k, v in got.items()}  # the latest bucket's Average
    triple = ("FrameQuartzLag", "InternalPipelineTime", "APILatency")
    common = [t for t in set(got["FrameQuartzLag"]) & set(got["InternalPipelineTime"])
              & set(got["APILatency"]) if len({got[k][t][1] for k in triple}) == 1]
    assert common, f"no minute holds the same frames in all three series: {got!r}"
    aligned = tuple(got[k][max(common)][0] for k in triple)

    op("cloudformation", "DescribeStacks")
    outs = {o["OutputKey"]: o["OutputValue"] for o in ctx.client("cloudformation").describe_stacks(
        StackName=stack)["Stacks"][0]["Outputs"]}
    op("ecs", "DescribeServices")
    svc = ctx.client("ecs").describe_services(cluster=outs["ClusterName"],
                                              services=[outs["ServiceName"]])["services"][0]
    op("ssm", "GetParametersByPath")
    params = []
    for page in ssm.get_paginator("get_parameters_by_path").paginate(Path=flag_root, Recursive=True):
        params.extend(p["Name"] for p in page.get("Parameters", []))
    hits = [n for n in params if "latency-mode" in n]
    assert len(hits) == 1, f"the flag search under {flag_root!r} found {hits!r} among {params!r}"
    op("ssm", "GetParameter")
    value = ssm.get_parameter(Name=hits[0])["Parameter"]["Value"]
    return ({"alarm": alarm, "latest": found, "aligned": aligned, "running": svc["runningCount"],
             "desired": svc["desiredCount"], "flag": (hits[0], value)}, tuple(fired))


# ===== helpers =====
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
        left = self.reap()
        assert not any(left.values()), f"side effects the stack delete does not release: {left!r}"


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


def _absent_error(fn) -> tuple[str, str]:
    """The (code, message) fn() raises; a success fails the check -- for asserting an ABSENCE."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
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


def _await_newest_minute(cw, names: dict, predicate, description: str, *, minutes: int = 1,
                         timeout_s: float = _FLIP_DEADLINE_S) -> tuple[float, float]:
    """Poll the alarmed series until its newest `minutes` 60 s buckets are consecutive and each
    bucket's (Minimum, Maximum) satisfies predicate; return the newest bucket's pair."""
    def newest():
        end = datetime.now(timezone.utc)
        pts = cw.get_metric_statistics(Namespace=names["flint_ns"], MetricName="Time",
                                       Dimensions=_dims("FrameQuartzLag"),
                                       StartTime=end - timedelta(minutes=5), EndTime=end, Period=60,
                                       Statistics=["Minimum", "Maximum"])["Datapoints"]
        last = sorted(pts, key=lambda p: p["Timestamp"])[-minutes:]
        if len(last) < minutes:
            return None
        stamps = [p["Timestamp"] for p in last]
        if any((b - a).total_seconds() != 60 for a, b in zip(stamps, stamps[1:])):
            return None
        return [(p["Minimum"], p["Maximum"]) for p in last]

    got = _poll(newest, lambda bs: bs is not None and all(predicate(*b) for b in bs),
                timeout_s=timeout_s, interval_s=5, description=description)
    return got[-1]


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
    """Invoke the backfill Lambda, with a BOUNDED retry for the two documented
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
    """The backfill ends 5 min before now; it also must end before the live task could
    have published anything, so the window it fills is the backfill's alone."""
    end = min(datetime.now(timezone.utc) - timedelta(minutes=5), applied_at - timedelta(minutes=1))
    return end.replace(second=0, microsecond=0)


def _backfill(cw, names: dict, *, end: datetime, seed: int) -> dict:
    """The reference backfill: ~3 h of healthy samples every ~12 s, all six Flint series plus
    the dependency, in batches of 1000. Seeded, so the sample count is known.

    The window starts 2 h 50 min back, not a full 3 h: measured, a sample already ~3 h old when
    PutMetricData accepts it is not served back by GetMetricStatistics, so a window touching the
    3 h edge makes the readback count a race against the clock."""
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
    for ns, batch in ((names["flint_ns"], flint), (names["dep_ns"], deps)):
        for i in range(0, len(batch), 1000):
            cw.put_metric_data(Namespace=ns, MetricData=batch[i:i + 1000])
    return {"start": start, "end": end, "n": len(stamps), "stamps": stamps}


def _count_in(stamps, lo: datetime, hi: datetime) -> int:
    return sum(1 for t in stamps if lo <= t < hi)


def _sample_count(cw, namespace: str, operation: str, lo: datetime, hi: datetime) -> int:
    pts = cw.get_metric_statistics(Namespace=namespace, MetricName="Time",
                                   Dimensions=_dims(operation), StartTime=lo, EndTime=hi,
                                   Period=3600, Statistics=["SampleCount"])["Datapoints"]
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
    """Apply the estate's template; register the delete BEFORE the create; return outputs."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    net = ctx.network()
    vpc, subnets = net.vpc_id, net.subnet_ids
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
        assert _delete() == 0, f"stack {stack} did not reach DELETE_COMPLETE"

    ctx.on_cleanup(_delete_net)  # BEFORE the create: a check killed mid-apply otherwise strands it
    applied_at = datetime.now(timezone.utc)
    params = {"Token": tok, "VpcId": vpc, "SubnetIds": ",".join(subnets),
              "FlintNamespace": names["flint_ns"], "DependencyNamespace": names["dep_ns"],
              "LatencyModeParamName": names["mode"], "PublishDepMetricsParamName": names["publish"],
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
