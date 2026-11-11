"""deep-logs-3-logacct-metric-extraction-policy-suppresses-emf-only-for-selected-group."""
from __future__ import annotations

import datetime as dt
import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-3-logacct-metric-extraction-policy-suppresses-emf-only-for-selected-group"
GROUP = "account-policies"
SERVICES = ["logs"]

_PREFIX = "sim2real-behav-logacct-"
_STREAM = "app"
_METRIC = "Hits"
_VALUE = 7


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """A Disabled METRIC_EXTRACTION_POLICY selecting one log group stops its EMF events producing
    datapoints while a sibling group's carry the emitted value; after deletion the group emits again.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    namespace = "Sim2Real/Behav/" + ctx.unique_name("logacct-")

    off = ctx.unique_name(_PREFIX + "emfoff-")
    on = ctx.unique_name(_PREFIX + "emfon-")
    for g in (off, on):
        logs.create_log_group(logGroupName=g, tags={"sim2real": CHECK[:200]})
        ctx.on_cleanup(lambda _g=g: logs.delete_log_group(logGroupName=_g))
        logs.create_log_stream(logGroupName=g, logStreamName=_STREAM)

    policy = ctx.unique_name(_PREFIX + "mep-")
    state = {"deleted": False}
    put = logs.put_account_policy(
        policyName=policy,
        policyType="METRIC_EXTRACTION_POLICY",
        policyDocument=json.dumps({"EmbeddedMetricFormat": {"Status": "Disabled"}}),
        selectionCriteria=f'LogGroupName IN ["{off}"]',
    )

    def _delete_policy() -> None:
        if not state["deleted"]:
            logs.delete_account_policy(policyName=policy, policyType="METRIC_EXTRACTION_POLICY")

    ctx.on_cleanup(_delete_policy)
    assert put["accountPolicy"]["selectionCriteria"] == f'LogGroupName IN ["{off}"]', (
        f"PutAccountPolicy echoed {put['accountPolicy']!r}"
    )
    described = _describe(logs, policy)
    assert len(described) == 1 and described[0]["policyType"] == "METRIC_EXTRACTION_POLICY", (
        f"DescribeAccountPolicies does not report this run's policy exactly once: {described!r}"
    )

    def _emf(label: str) -> str:
        return json.dumps(
            {
                "_aws": {
                    "Timestamp": _now_ms(),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": namespace,
                            "Dimensions": [["Grp"]],
                            "Metrics": [{"Name": _METRIC, "Unit": "Count"}],
                        }
                    ],
                },
                "Grp": label,
                _METRIC: _VALUE,
            }
        )

    def _write(group: str, label: str) -> None:
        resp = logs.put_log_events(
            logGroupName=group,
            logStreamName=_STREAM,
            logEvents=[{"timestamp": _now_ms(), "message": _emf(label)}],
        )
        assert not resp.get("rejectedLogEventsInfo"), f"rejected on {group!r}: {resp!r}"

    def _stats(label: str) -> tuple[float, float]:
        """(Maximum, SampleCount) over every datapoint for Grp=label."""
        now = dt.datetime.now(dt.timezone.utc)
        queries = [
            {
                "Id": stat.lower(),
                "MetricStat": {
                    "Metric": {
                        "Namespace": namespace,
                        "MetricName": _METRIC,
                        "Dimensions": [{"Name": "Grp", "Value": label}],
                    },
                    "Period": 60,
                    "Stat": stat,
                },
            }
            for stat in ("Maximum", "SampleCount")
        ]
        r = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=now - dt.timedelta(minutes=30),
            EndTime=now + dt.timedelta(minutes=2),
        )
        by_id = {q["Id"]: q["Values"] for q in r["MetricDataResults"]}
        return max(by_id["maximum"], default=0.0), sum(by_id["samplecount"])

    # The unselected group's datapoint is the barrier: EMF extraction works in this namespace.
    # The selected group is written only after it, so the policy has had the barrier's time to
    # take effect before any event it must suppress.
    on_writes = 0
    started = time.monotonic()
    deadline = started + _budget_s(ctx, 180.0)
    while True:
        _write(on, "on")
        on_writes += 1
        time.sleep(2.0)
        on_max, on_count = _stats("on")
        if on_count > 0:
            break
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError("a datapoint for the unselected group's EMF metric: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"no datapoint for the UNSELECTED group's EMF metric within "
            f"{time.monotonic() - started:.0f}s in {namespace!r}; "
            f"EMF extraction itself is not working, so nothing below would mean anything"
        )
    assert on_max == _VALUE, (
        f"the EMF datapoint must carry the emitted value {_VALUE}, GetMetricData Maximum was "
        f"{on_max!r}"
    )

    # The policy type can only disable EMF, so absence is proven by contrast: once every
    # unselected-group event has its sample, each selected-group event, written before the last
    # unselected one, has had the same chance to produce one.
    for _ in range(3):
        _write(off, "off")
        _write(on, "on")
        on_writes += 1
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    while True:
        on_count2 = _stats("on")[1]
        if on_count2 >= on_writes:
            break
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError("every unselected-group EMF event's sample: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"the unselected group's {on_writes} EMF events produced only {on_count2} sample(s) "
            f"-- the contrast is void"
        )
        time.sleep(2.0)
    off_max, off_count = _stats("off")
    assert off_count == 0, (
        f"{off!r} is selected by a Disabled METRIC_EXTRACTION_POLICY, yet its EMF events "
        f"produced {off_count} sample(s) (max {off_max!r}) while the unselected group's "
        f"{on_writes} events produced {on_count2}"
    )

    logs.delete_account_policy(policyName=policy, policyType="METRIC_EXTRACTION_POLICY")
    state["deleted"] = True
    assert _describe(logs, policy) == [], "DeleteAccountPolicy left the policy described"
    after_started = time.monotonic()
    deadline = after_started + _budget_s(ctx, 180.0)
    while True:
        _write(off, "off-after")
        time.sleep(2.0)
        after_max, after_count = _stats("off-after")
        if after_count > 0:
            break
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError("a post-deletion EMF datapoint: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"after DeleteAccountPolicy, {off!r}'s EMF events still produced no datapoint "
            f"within {time.monotonic() - after_started:.0f}s"
        )
    assert after_max == _VALUE, f"post-deletion datapoint Maximum {after_max!r} != {_VALUE}"
    assert _stats("off")[1] == 0, (
        "EMF events written while the policy was in force must not be back-filled into "
        f"metrics after it is deleted; Grp=off now has {_stats('off')[1]} sample(s)"
    )


def _describe(logs, policy: str) -> list:
    found = []
    token = None
    while True:
        kwargs = {"policyType": "METRIC_EXTRACTION_POLICY"}
        if token is not None:
            kwargs["nextToken"] = token
        page = logs.describe_account_policies(**kwargs)
        found.extend(p for p in page.get("accountPolicies", []) if p["policyName"] == policy)
        token = page.get("nextToken")
        if not token:
            return found


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _now_ms() -> int:
    return int(time.time() * 1000)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
