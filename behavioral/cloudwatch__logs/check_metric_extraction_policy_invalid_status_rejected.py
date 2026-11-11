"""metric-extraction-policy-invalid-status-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-extraction-policy-invalid-status-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "logs"]

_POLICY_TYPE = "METRIC_EXTRACTION_POLICY"

#: The EMF metric and EMFDisabledErrors typically become readable 20-40 s after PutLogEvents.
_APPEAR_TIMEOUT_S = 200
#: How long a reading must hold unchanged.
_STABLE_WINDOW_S = 10
#: How long the absences are held after the positive readings settle.
_HOLD_S = 10


_NO_ERROR = "<no error raised: the call succeeded>"


def _error(fn):
    """(code, message) of the ClientError fn() raised; a non-tuple sentinel if it SUCCEEDED."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _NO_ERROR


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


def _assert_stays(probe, expected, *, hold_s, interval_s=2, description="reading"):
    """Assert probe() == expected continuously for hold_s."""
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description} became {got!r}, expected it to stay {expected!r} for {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


# timing:real-time — metric: 34 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1", "resource:account-singleton:logs-account-policy", "timing:real-time",
)
def run(ctx) -> None:
    """A METRIC_EXTRACTION_POLICY with Status other than the exact "Disabled" is rejected with no effect:
    nothing is stored and EMF extraction stays on, while a well-formed policy suppresses extraction.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    t_start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=1)

    rejected_group = ctx.unique_name("sim2real-behav-emfrej-")
    accepted_group = ctx.unique_name("sim2real-behav-emfacc-")
    rejected_policy = ctx.unique_name("sim2real-behav-mep-rej-")
    accepted_policy = ctx.unique_name("sim2real-behav-mep-acc-")
    ns_rejected = ctx.unique_name("sim2real-behav-ns-rej-")
    ns_accepted = ctx.unique_name("sim2real-behav-ns-acc-")

    for g in (rejected_group, accepted_group):
        logs.create_log_group(logGroupName=g, tags={"sim2real:managed": "true"})
        ctx.on_cleanup(lambda g=g: _ignore_not_found(lambda: logs.delete_log_group(logGroupName=g)))
        logs.put_retention_policy(logGroupName=g, retentionInDays=1)
        logs.create_log_stream(logGroupName=g, logStreamName="s")

    # A target that wrongly ACCEPTS the malformed policy has stored account-scoped state, so the
    # delete is registered before the call, not after an assertion that may abort.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_account_policy(
        policyName=rejected_policy, policyType=_POLICY_TYPE)))
    # AWS rejects every Status but the exact "Disabled"; "Enabled" is the likeliest to be accepted.
    for status in ("Enabled", "DISABLED"):
        err = _error(lambda status=status: logs.put_account_policy(
            policyName=rejected_policy, policyType=_POLICY_TYPE,
            policyDocument=json.dumps({"EmbeddedMetricFormat": {"Status": status}}),
            scope="ALL", selectionCriteria=f'LogGroupName IN ["{rejected_group}"]',
        ))
        expected = ("InvalidParameterException", "Invalid json policy document")
        assert err == expected, (
            f"PutAccountPolicy with EmbeddedMetricFormat.Status={status!r} returned {err!r}; "
            f"real AWS accepts only the exact string 'Disabled' and rejects this with {expected!r}"
        )
    stored = logs.describe_account_policies(
        policyType=_POLICY_TYPE, policyName=rejected_policy)["accountPolicies"]
    assert stored == [], f"the rejected PutAccountPolicy left a stored policy: {stored!r}"

    # Positive control: the well-formed document IS accepted, for the other group.
    ok = logs.put_account_policy(
        policyName=accepted_policy, policyType=_POLICY_TYPE,
        policyDocument=json.dumps({"EmbeddedMetricFormat": {"Status": "Disabled"}}),
        scope="ALL", selectionCriteria=f'LogGroupName IN ["{accepted_group}"]',
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_account_policy(
        policyName=accepted_policy, policyType=_POLICY_TYPE)))
    assert ok["accountPolicy"]["policyName"] == accepted_policy, f"PutAccountPolicy echoed {ok!r}"
    listed = logs.describe_account_policies(
        policyType=_POLICY_TYPE, policyName=accepted_policy)["accountPolicies"]
    assert [p["selectionCriteria"] for p in listed] == [
        f'LogGroupName IN ["{accepted_group}"]'
    ], f"DescribeAccountPolicies for the accepted policy returned {listed!r}"

    def _emf(namespace):
        ts = int(time.time() * 1000)
        return {"timestamp": ts, "message": json.dumps({
            "_aws": {"Timestamp": ts, "CloudWatchMetrics": [{
                "Namespace": namespace, "Dimensions": [["Svc"]],
                "Metrics": [{"Name": "Probe", "Unit": "Count"}]}]},
            "Svc": "obs", "Probe": 11})}

    for g, ns in ((rejected_group, ns_rejected), (accepted_group, ns_accepted)):
        r = logs.put_log_events(logGroupName=g, logStreamName="s", logEvents=[_emf(ns)])
        assert "rejectedLogEventsInfo" not in r, f"EMF PutLogEvents into {g!r} rejected: {r!r}"

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

    def _present():
        extracted = _sum(ns_rejected, "Probe", svc)
        disabled = _sum("AWS/Logs", "EMFDisabledErrors",
                        [{"Name": "LogGroupName", "Value": accepted_group}])
        if extracted is None or disabled is None:
            return None
        return (extracted, disabled)

    # An over-permissive target treats any stored policy as "extraction disabled" for its group.
    extracted, disabled = _poll_until_stable(
        _present, ctx=ctx, window_s=_STABLE_WINDOW_S, timeout_s=_APPEAR_TIMEOUT_S,
        description="the EMF metric from the rejected-policy group and EMFDisabledErrors for "
                    "the accepted-policy group",
    )
    assert extracted == (11.0, 1.0), (
        f"{ns_rejected}/Probe read (Sum, SampleCount)={extracted!r}, expected (11.0, 1.0): the "
        f"rejected policy must not have disabled extraction for {rejected_group!r}"
    )
    assert disabled[0] == 1.0, (
        f"EMFDisabledErrors for the accepted-policy group read Sum={disabled[0]!r}, expected 1.0 "
        f"-- the positive control: the well-formed policy suppresses its one EMF document"
    )

    _assert_stays(
        lambda: {
            "rejected-group EMFDisabledErrors": _sum(
                "AWS/Logs", "EMFDisabledErrors",
                [{"Name": "LogGroupName", "Value": rejected_group}]),
            "accepted-group extracted metric": _sum(ns_accepted, "Probe", svc),
        },
        {"rejected-group EMFDisabledErrors": None, "accepted-group extracted metric": None},
        hold_s=_HOLD_S,
        description="EMFDisabledErrors for the rejected-policy group and the suppressed "
                    "namespace of the accepted-policy group",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
