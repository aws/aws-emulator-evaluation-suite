"""obs-logs-3-service-usage-and-emf-policy-metrics."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-logs-3-service-usage-and-emf-policy-metrics"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "logs"]

# The four-key service-usage dimension set CloudWatch Logs publishes per API, in both
# AWS/Logs and AWS/Usage.
_USAGE_DIMS = [
    {"Name": "Service", "Value": "Logs"},
    {"Name": "Class", "Value": "None"},
    {"Name": "Type", "Value": "API"},
    {"Name": "Resource", "Value": "PutLogEvents"},
]

# The only document AWS accepts for METRIC_EXTRACTION_POLICY: Status must be exactly
# "Disabled" ("DISABLED", "Enabled" etc. are invalid). The model types it as a bare string.
_DISABLE_DOC = json.dumps({"EmbeddedMetricFormat": {"Status": "Disabled"}})

# An ill-formed group name fails InvalidParameterException and counts in ErrorCount. A missing
# group fails ResourceNotFoundException, which counts in CallCount but not in ErrorCount.
_INVALID_GROUP_NAME = "sim2real bad name!*"
_MISSING_MESSAGE = "The specified log group does not exist."
_INVALID_MESSAGE = (
    "1 validation error detected: Value at 'logGroupName' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: [\\.\\-_/#A-Za-z0-9]+"
)

_N_VALID = 5
_N_MISSING = 3
_N_INVALID = 3
_N_EMF = 2  # one into the policy-covered group, one into the uncovered control group
_N_PUT_LOG_EVENTS = _N_VALID + _N_MISSING + _N_INVALID + _N_EMF

# These metrics are typically readable 20-40 s after the calls return; 200 s leaves headroom.
_APPEAR_TIMEOUT_S = 200
#: How long a reading must hold unchanged.
_STABLE_WINDOW_S = 10
#: How long the absences are held after the positive readings settle.
_HOLD_S = 10


def _error(fn):
    """(Error.Code, Error.Message) fn() raised. A SUCCESS raises: the write must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, ok, *, ctx, timeout_s, interval_s=2, description="reading"):
    """Return probe()'s value as soon as ok(value) holds; fail naming the last reading."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if ok(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not reached within {timeout_s}s; last reading {last!r}")


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
    """Return probe()'s value once two non-empty readings >= window_s apart are EQUAL.

    Stopping at the first reading that meets a target can only detect an UNDER-count; holding
    the value for window_s catches an over-count too.
    """
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
    """Assert probe() == expected continuously for hold_s. Absence proven, not sampled once."""
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description} became {got!r}, expected it to stay {expected!r} for {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


# timing:real-time — metric: 47 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Monitoring-CloudWatch-Metrics.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1", "resource:account-singleton:logs-account-policy", "timing:real-time",
)
def run(ctx) -> None:
    """Logs meters PutLogEvents as CallCount (AWS/Logs, AWS/Usage) and ErrorCount (AWS/Logs only).
    A METRIC_EXTRACTION_POLICY scoped to one group suppresses only its EMF, as EMFDisabledErrors.
    Account-wide counters are lower bounds; exact values only on series this check minted.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    t_start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=1)

    covered = ctx.unique_name("sim2real-behav-emfoff-")   # in the policy's selection criteria
    control = ctx.unique_name("sim2real-behav-emfon-")    # identical traffic, not selected
    missing = ctx.unique_name("sim2real-behav-missing-")  # never created
    policy = ctx.unique_name("sim2real-behav-mep-")
    ns_covered = ctx.unique_name("sim2real-behav-ns-off-")
    ns_control = ctx.unique_name("sim2real-behav-ns-on-")

    for g in (covered, control):
        logs.create_log_group(logGroupName=g, tags={"sim2real:managed": "true"})
        ctx.on_cleanup(lambda g=g: _ignore_not_found(lambda: logs.delete_log_group(logGroupName=g)))
        logs.put_retention_policy(logGroupName=g, retentionInDays=1)
        logs.create_log_stream(logGroupName=g, logStreamName="s")
    # A target that wrongly accepted a PutLogEvents into a missing group may have created it.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_log_group(logGroupName=missing)))

    # ---- the account policy, scoped to the covered group only ------------------------------ #
    put = logs.put_account_policy(
        policyName=policy, policyType="METRIC_EXTRACTION_POLICY", policyDocument=_DISABLE_DOC,
        scope="ALL", selectionCriteria=f'LogGroupName IN ["{covered}"]',
    )
    # Account-scoped state: deleting it is non-negotiable, so it is registered before any assert.
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_account_policy(
        policyName=policy, policyType="METRIC_EXTRACTION_POLICY")))
    ap = put["accountPolicy"]
    assert (ap["policyName"], ap["policyType"], ap["scope"]) == (
        policy, "METRIC_EXTRACTION_POLICY", "ALL"
    ), f"PutAccountPolicy echoed {ap!r}"
    assert json.loads(ap["policyDocument"]) == json.loads(_DISABLE_DOC), (
        f"policyDocument echoed as {ap['policyDocument']!r}, expected {_DISABLE_DOC!r}"
    )
    assert ap["selectionCriteria"] == f'LogGroupName IN ["{covered}"]', (
        f"selectionCriteria echoed as {ap['selectionCriteria']!r}"
    )

    # ---- part 1: 5 valid, 3 missing-group, 3 invalid-name PutLogEvents ---------------------- #
    for i in range(_N_VALID):
        r = logs.put_log_events(
            logGroupName=control, logStreamName="s",
            logEvents=[{"timestamp": int(time.time() * 1000), "message": f"plain line {i}"}],
        )
        assert "rejectedLogEventsInfo" not in r, f"valid PutLogEvents rejected events: {r!r}"

    def _put_to(group):
        return lambda: logs.put_log_events(
            logGroupName=group, logStreamName="s",
            logEvents=[{"timestamp": int(time.time() * 1000), "message": "should not land"}],
        )

    missing_errors = [_error(_put_to(missing)) for _ in range(_N_MISSING)]
    assert missing_errors == [("ResourceNotFoundException", _MISSING_MESSAGE)] * _N_MISSING, (
        f"PutLogEvents into the never-created group {missing!r} returned {missing_errors!r}; "
        f"each must fail ResourceNotFoundException {_MISSING_MESSAGE!r}"
    )
    invalid_errors = [_error(_put_to(_INVALID_GROUP_NAME)) for _ in range(_N_INVALID)]
    assert invalid_errors == [("InvalidParameterException", _INVALID_MESSAGE)] * _N_INVALID, (
        f"PutLogEvents into the ill-formed group name {_INVALID_GROUP_NAME!r} returned "
        f"{invalid_errors!r}; each must fail InvalidParameterException {_INVALID_MESSAGE!r}"
    )
    # Effect absent: the failed writes created nothing.
    found = logs.describe_log_groups(logGroupNamePrefix=missing)["logGroups"]
    assert found == [], f"a failed PutLogEvents materialised log group(s) {found!r}"

    # ---- part 2: one EMF line into each group ------------------------------------------- #
    def _emf(namespace):
        ts = int(time.time() * 1000)
        return {"timestamp": ts, "message": json.dumps({
            "_aws": {"Timestamp": ts, "CloudWatchMetrics": [{
                "Namespace": namespace, "Dimensions": [["Svc"]],
                "Metrics": [{"Name": "Probe", "Unit": "Count"}]}]},
            "Svc": "obs", "Probe": 7})}

    for g, ns in ((covered, ns_covered), (control, ns_control)):
        r = logs.put_log_events(logGroupName=g, logStreamName="s", logEvents=[_emf(ns)])
        # The log write SUCCEEDED, so any metric absence below is an extraction decision.
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

    def _counters():
        return {
            "logs_calls": _sum("AWS/Logs", "CallCount", _USAGE_DIMS),
            "usage_calls": _sum("AWS/Usage", "CallCount", _USAGE_DIMS),
            "logs_errors": _sum("AWS/Logs", "ErrorCount", _USAGE_DIMS),
            "account_calls": _sum("AWS/Logs", "CallCount", []),
            "account_errors": _sum("AWS/Logs", "ErrorCount", []),
        }

    floors = {
        "logs_calls": _N_PUT_LOG_EVENTS,
        "usage_calls": _N_PUT_LOG_EVENTS,
        "logs_errors": _N_INVALID,
        # The account-level series is AWS/Logs with NO dimensions, summing every Logs API.
        "account_calls": _N_PUT_LOG_EVENTS,
        "account_errors": _N_INVALID,
    }
    counters = _poll_until(
        _counters,
        lambda c: all(c[k] is not None and c[k][0] >= v for k, v in floors.items()),
        ctx=ctx,
        timeout_s=_APPEAR_TIMEOUT_S,
        description=f"service-usage counters reaching their floors {floors!r}",
    )
    assert counters["logs_calls"][0] >= _N_PUT_LOG_EVENTS, (
        f"AWS/Logs CallCount{{Resource=PutLogEvents}} Sum={counters['logs_calls'][0]!r}; this "
        f"check issued {_N_PUT_LOG_EVENTS} PutLogEvents calls, failed ones included"
    )
    assert counters["usage_calls"][0] >= _N_PUT_LOG_EVENTS, (
        f"AWS/Usage CallCount{{Resource=PutLogEvents}} Sum={counters['usage_calls'][0]!r}, "
        f"expected >= {_N_PUT_LOG_EVENTS}: AWS/Usage mirrors CallCount for Logs"
    )
    assert counters["logs_errors"][0] >= _N_INVALID, (
        f"AWS/Logs ErrorCount{{Resource=PutLogEvents}} Sum={counters['logs_errors'][0]!r}, "
        f"expected >= {_N_INVALID} from the InvalidParameterException calls"
    )
    assert counters["account_calls"][0] >= _N_PUT_LOG_EVENTS, (
        f"dimensionless (account-level) AWS/Logs CallCount Sum={counters['account_calls'][0]!r}"
    )
    assert counters["account_errors"][0] >= _N_INVALID, (
        f"dimensionless (account-level) AWS/Logs ErrorCount Sum={counters['account_errors'][0]!r}"
    )

    # ---- EMF: exact values on series only this check can occupy ----------------------------- #
    dim_covered = [{"Name": "LogGroupName", "Value": covered}]
    dim_control = [{"Name": "LogGroupName", "Value": control}]
    svc_dim = [{"Name": "Svc", "Value": "obs"}]

    def _emf_exact():
        disabled = _sum("AWS/Logs", "EMFDisabledErrors", dim_covered)
        extracted = _sum(ns_control, "Probe", svc_dim)
        ingested = _sum("AWS/Logs", "IncomingLogEvents", dim_covered)
        if disabled is None or extracted is None or ingested is None:
            return None
        return (disabled, extracted, ingested)

    disabled, extracted, ingested = _poll_until_stable(
        _emf_exact, ctx=ctx, window_s=_STABLE_WINDOW_S, timeout_s=_APPEAR_TIMEOUT_S,
        description=(f"EMFDisabledErrors for {covered!r}, the control namespace's extracted "
                     f"metric, and IncomingLogEvents for the covered group"),
    )
    assert disabled[0] == 1.0, (
        f"AWS/Logs EMFDisabledErrors{{LogGroupName={covered}}} stabilised at Sum={disabled[0]!r}; "
        f"exactly one EMF document was written into the policy-covered group"
    )
    assert ingested == (1.0, 1.0), (
        f"IncomingLogEvents for the covered group read {ingested!r}; the EMF line must still be "
        f"INGESTED as a log event while its metrics are suppressed"
    )
    assert extracted == (7.0, 1.0), (
        f"the uncovered control group's EMF metric {ns_control}/Probe read (Sum, SampleCount)="
        f"{extracted!r}, expected (7.0, 1.0) -- extraction must stay ON outside the selection"
    )
    stored = logs.filter_log_events(logGroupName=covered, filterPattern='{ $.Probe = 7 }')["events"]
    assert len(stored) == 1 and json.loads(stored[0]["message"])["_aws"]["CloudWatchMetrics"][0][
        "Namespace"] == ns_covered, (
        f"the suppressed EMF document is not readable from {covered!r}: {stored!r}"
    )

    # ---- absences, held across a publication interval -------------------------------------- #
    absent = {
        f"{ns_covered}/Probe (EMF line in the policy-covered group)":
            lambda: _sum(ns_covered, "Probe", svc_dim),
        "AWS/Usage ErrorCount{Resource=PutLogEvents} (ErrorCount is AWS/Logs-only)":
            lambda: _sum("AWS/Usage", "ErrorCount", _USAGE_DIMS),
        f"AWS/Logs EMFDisabledErrors for the uncovered control group {control}":
            lambda: _sum("AWS/Logs", "EMFDisabledErrors", dim_control),
    }
    _assert_stays(
        lambda: {k: p() for k, p in absent.items()}, {k: None for k in absent},
        hold_s=_HOLD_S,
        description="the suppressed EMF namespace, AWS/Usage ErrorCount, and control-group "
                    "EMFDisabledErrors",
    )

    # ---- teardown of the account policy, verified ----------------------------------------- #
    logs.delete_account_policy(policyName=policy, policyType="METRIC_EXTRACTION_POLICY")
    left = logs.describe_account_policies(
        policyType="METRIC_EXTRACTION_POLICY", policyName=policy)["accountPolicies"]
    assert left == [], f"DeleteAccountPolicy left {left!r} behind"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
