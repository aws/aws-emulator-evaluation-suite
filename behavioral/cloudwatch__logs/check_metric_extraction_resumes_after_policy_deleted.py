"""metric-extraction-resumes-after-policy-deleted."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-extraction-resumes-after-policy-deleted"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "logs"]

_POLICY_TYPE = "METRIC_EXTRACTION_POLICY"
_APPEAR_TIMEOUT_S = 200
#: How long a reading must hold unchanged.
_STABLE_WINDOW_S = 10


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until_stable(probe, *, ctx, window_s, timeout_s, interval_s=2, description="reading"):
    """Return probe()'s value once two non-empty readings >= window_s apart are EQUAL."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    anchor, anchor_t, last = None, 0.0, None
    while time.monotonic() < deadline:
        last = probe()
        now = time.monotonic()
        if not last:
            anchor, anchor_t = None, 0.0
        elif last != anchor:
            anchor, anchor_t = last, now
        elif now - anchor_t >= window_s:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} never held one value for {window_s}s within {timeout_s}s; "
        f"last reading was {last!r}"
    )


# timing:real-time — metric: 48 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html
@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1", "resource:account-singleton:logs-account-policy", "timing:real-time")
def run(ctx) -> None:
    """While a METRIC_EXTRACTION_POLICY selects a group, an EMF document yields one EMFDisabledErrors and
    no metric; after DeleteAccountPolicy the next document into the same stream is extracted again.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    t_start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=1)

    group = ctx.unique_name("sim2real-behav-emfres-")
    policy = ctx.unique_name("sim2real-behav-mep-res-")
    ns_during = ctx.unique_name("sim2real-behav-ns-during-")
    ns_after = ctx.unique_name("sim2real-behav-ns-after-")

    logs.create_log_group(logGroupName=group, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_log_group(logGroupName=group)))
    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    logs.create_log_stream(logGroupName=group, logStreamName="s")

    logs.put_account_policy(
        policyName=policy, policyType=_POLICY_TYPE,
        policyDocument=json.dumps({"EmbeddedMetricFormat": {"Status": "Disabled"}}),
        scope="ALL", selectionCriteria=f'LogGroupName IN ["{group}"]',
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_account_policy(
        policyName=policy, policyType=_POLICY_TYPE)))

    def _emf(namespace, value):
        ts = int(time.time() * 1000)
        return [{"timestamp": ts, "message": json.dumps({
            "_aws": {"Timestamp": ts, "CloudWatchMetrics": [{
                "Namespace": namespace, "Dimensions": [["Svc"]],
                "Metrics": [{"Name": "Probe", "Unit": "Count"}]}]},
            "Svc": "obs", "Probe": value})}]

    def _sum(namespace, metric, dims):
        dps = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims, StartTime=t_start,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]
        if not dps:
            return None
        return (sum(d["Sum"] for d in dps), sum(d["SampleCount"] for d in dps))

    svc = [{"Name": "Svc", "Value": "obs"}]
    dim_group = [{"Name": "LogGroupName", "Value": group}]

    # ---- policy in force ------------------------------------------------------------------- #
    r = logs.put_log_events(logGroupName=group, logStreamName="s",
                            logEvents=_emf(ns_during, 5))
    assert "rejectedLogEventsInfo" not in r, f"PutLogEvents rejected events: {r!r}"

    def _phase1():
        disabled = _sum("AWS/Logs", "EMFDisabledErrors", dim_group)
        if disabled is None:
            return None
        return (disabled, _sum(ns_during, "Probe", svc))

    disabled_1, during = _poll_until_stable(
        _phase1, ctx=ctx, window_s=_STABLE_WINDOW_S, timeout_s=_APPEAR_TIMEOUT_S,
        description=f"EMFDisabledErrors for {group!r} with the policy in force",
    )
    assert disabled_1[0] == 1.0, (
        f"EMFDisabledErrors with the policy in force read Sum={disabled_1[0]!r}, expected 1.0 "
        f"for the one EMF document written"
    )
    assert during is None, (
        f"{ns_during}/Probe read {during!r} while the policy was in force; the suppressed "
        f"document must produce no datapoint"
    )

    # ---- policy deleted, same group, same stream ------------------------------------------- #
    # Extraction is decided asynchronously against the policy store, so the policy is deleted only
    # after the first line's suppression was observed and held; otherwise the order is a race.
    logs.delete_account_policy(policyName=policy, policyType=_POLICY_TYPE)
    left = logs.describe_account_policies(
        policyType=_POLICY_TYPE, policyName=policy)["accountPolicies"]
    assert left == [], f"DeleteAccountPolicy left {left!r}"

    r = logs.put_log_events(logGroupName=group, logStreamName="s",
                            logEvents=_emf(ns_after, 9))
    assert "rejectedLogEventsInfo" not in r, f"PutLogEvents rejected events: {r!r}"

    def _phase2():
        after = _sum(ns_after, "Probe", svc)
        if after is None:
            return None
        return (after, _sum("AWS/Logs", "EMFDisabledErrors", dim_group),
                _sum(ns_during, "Probe", svc))

    after, disabled_2, during_2 = _poll_until_stable(
        _phase2, ctx=ctx, window_s=_STABLE_WINDOW_S, timeout_s=_APPEAR_TIMEOUT_S,
        description=f"{ns_after}/Probe after the policy was deleted",
    )
    assert after == (9.0, 1.0), (
        f"after DeleteAccountPolicy the EMF document into {group!r} extracted (Sum, SampleCount)="
        f"{after!r}, expected (9.0, 1.0): extraction must resume for the same group"
    )
    assert disabled_2 is not None and disabled_2[0] == 1.0, (
        f"EMFDisabledErrors for {group!r} moved to {disabled_2!r} after the delete; the "
        f"post-delete document must not be counted as suppressed"
    )
    assert during_2 is None, (
        f"the document suppressed in phase 1 materialised later as {during_2!r}; deleting the "
        f"policy must not retroactively extract it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
