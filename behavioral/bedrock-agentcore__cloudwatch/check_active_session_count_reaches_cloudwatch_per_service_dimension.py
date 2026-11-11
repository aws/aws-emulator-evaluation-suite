"""active-session-count-reaches-cloudwatch-per-service-dimension."""
from __future__ import annotations

import datetime as _dt
import time

from behavioral_harness import tags

CHECK = "active-session-count-reaches-cloudwatch-per-service-dimension"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore", "cloudwatch"]

# The AWS-managed built-in code interpreter; usable with no prior CreateCodeInterpreter call.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-start-session.html
_IDENTIFIER = "aws.codeinterpreter.v1"
_METRIC_NAMESPACE = "AWS/Bedrock-AgentCore"
_METRIC_NAME = "ActiveSessionCount"
_CODE_INTERPRETER_DIM = [{"Name": "Service", "Value": "AgentCore.CodeInterpreter"}]
_BROWSER_DIM = [{"Name": "Service", "Value": "AgentCore.Browser"}]
_SESSIONS = 2
_BASELINE_MINUTES = 5


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-service-provided.html
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Two READY Code Interpreter sessions raise AWS/Bedrock-AgentCore ActiveSessionCount to >= 2
    (Unit Count, listed by ListMetrics) under Service=AgentCore.CodeInterpreter, while the
    Service=AgentCore.Browser series, with no session started, stays below that peak."""
    agentcore = ctx.client("bedrock-agentcore")
    cloudwatch = ctx.client("cloudwatch")

    # BASELINE at the consumer, before the producer does anything. This is what makes the ">= 2"
    # below a delta rather than a reading a target could satisfy with a constant. The window is
    # the last few minutes, so sessions of an earlier, finished run in the account fall outside it.
    baseline_end = _dt.datetime.now(_dt.timezone.utc)
    baseline_start = baseline_end - _dt.timedelta(minutes=_BASELINE_MINUTES)
    baseline = _max_datapoint(cloudwatch, _CODE_INTERPRETER_DIM, baseline_start, baseline_end)
    assert baseline < float(_SESSIONS), (
        f"before this check started a single session, {_METRIC_NAMESPACE}/{_METRIC_NAME} for "
        f"Service=AgentCore.CodeInterpreter already reported a maximum of {baseline!r} over the "
        f"preceding {_BASELINE_MINUTES} minutes, which is >= the {_SESSIONS} this check is about "
        "to start: another AgentCore session is active in this account, or the target publishes "
        "a constant"
    )

    session_ids = []
    for index in range(_SESSIONS):
        session_id = agentcore.start_code_interpreter_session(
            codeInterpreterIdentifier=_IDENTIFIER,
            name=ctx.unique_name(f"simparity-metric-{index}-")[:100],
            sessionTimeoutSeconds=900,
        )["sessionId"]
        session_ids.append(session_id)
        ctx.on_cleanup(
            lambda sid=session_id: agentcore.stop_code_interpreter_session(
                codeInterpreterIdentifier=_IDENTIFIER, sessionId=sid
            )
        )
    assert len(set(session_ids)) == _SESSIONS, (
        f"expected {_SESSIONS} distinct session ids, got {session_ids!r}"
    )

    # Ground the word "active": every session must report READY at the producer before anything
    # is demanded of the consumer.
    for session_id in session_ids:
        status = _poll_until(
            lambda sid=session_id: agentcore.get_code_interpreter_session(
                codeInterpreterIdentifier=_IDENTIFIER, sessionId=sid
            )["status"],
            lambda s: s in ("READY", "TERMINATED"),
            timeout_s=60.0,
            interval_s=3.0,
            description=f"code interpreter session {session_id} reached a settled status",
        )
        assert status == "READY", (
            f"session {session_id} reported status {status!r}, expected 'READY' before the "
            "metric can be expected to count it"
        )
    ready_at = _dt.datetime.now(_dt.timezone.utc)
    window_start = ready_at.replace(second=0, microsecond=0)

    # The join: the delivered signal at the CONSUMER. Bounded poll that RAISES.
    observed = _poll_until(
        lambda: _max_datapoint(
            cloudwatch,
            _CODE_INTERPRETER_DIM,
            window_start,
            _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=1),
        ),
        lambda value: value >= float(_SESSIONS),
        # AgentCore publishes once per minute per service type; the bound covers delivery lag.
        timeout_s=480.0,
        interval_s=20.0,
        description=(
            f"{_METRIC_NAMESPACE}/{_METRIC_NAME} for Service=AgentCore.CodeInterpreter reported "
            f"at least {_SESSIONS} in the window starting {window_start.isoformat()}"
        ),
    )
    assert observed >= float(_SESSIONS), (
        f"{_METRIC_NAMESPACE}/{_METRIC_NAME} peaked at {observed!r} for "
        f"Service=AgentCore.CodeInterpreter while {_SESSIONS} sessions were READY"
    )

    # Pin the unit and that the datapoint falls inside the window (no stale pre-run datapoint).
    datapoints = _datapoints(
        cloudwatch,
        _CODE_INTERPRETER_DIM,
        window_start,
        _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=1),
    )
    qualifying = [d for d in datapoints if d["Maximum"] >= float(_SESSIONS)]
    assert qualifying, (
        f"no datapoint in {datapoints!r} reached {_SESSIONS} even though the poll above said one "
        "had; the metric store is not returning stable reads"
    )
    for datapoint in qualifying:
        assert datapoint["Unit"] == "Count", (
            f"the qualifying datapoint reports Unit {datapoint['Unit']!r}, expected 'Count' for a "
            f"session-count gauge: {datapoint!r}"
        )
        assert datapoint["Timestamp"] >= window_start, (
            f"the qualifying datapoint is stamped {datapoint['Timestamp'].isoformat()}, before "
            f"the window start {window_start.isoformat()} — a stale datapoint cannot be evidence "
            "that THESE sessions were counted"
        )

    # ListMetrics indexes a series first seen in an account later than GetMetricStatistics
    # serves it, so the read is a bounded poll that raises on timeout.
    listed = _poll_until(
        lambda: cloudwatch.list_metrics(
            Namespace=_METRIC_NAMESPACE,
            MetricName=_METRIC_NAME,
            Dimensions=[{"Name": "Service", "Value": "AgentCore.CodeInterpreter"}],
        )["Metrics"],
        bool,
        timeout_s=600.0,
        interval_s=30.0,
        description=(
            f"ListMetrics listed {_METRIC_NAMESPACE}/{_METRIC_NAME} with "
            "Dimensions=[Service=AgentCore.CodeInterpreter]"
        ),
    )
    assert listed, (
        f"ListMetrics found no {_METRIC_NAMESPACE}/{_METRIC_NAME} with "
        "Dimensions=[Service=AgentCore.CodeInterpreter], even though GetMetricStatistics just "
        f"returned {observed!r} for exactly that series"
    )
    for metric in listed:
        assert metric["Namespace"] == _METRIC_NAMESPACE, (
            f"ListMetrics returned namespace {metric['Namespace']!r}, expected "
            f"{_METRIC_NAMESPACE!r}"
        )
        assert {(d["Name"], d["Value"]) for d in metric["Dimensions"]} == {
            ("Service", "AgentCore.CodeInterpreter")
        }, (
            f"ListMetrics returned dimensions {metric['Dimensions']!r}, expected exactly "
            "[Service=AgentCore.CodeInterpreter]"
        )

    # The twin control in the same window: the Browser dimension, for which this check started no
    # session at all, must not have been credited with this check's sessions. A target publishing
    # one undifferentiated counter under every Service value reports the same peak under both
    # dimensions and fails here while passing everything above. The bound is relative to the
    # peak this check produced, not an absolute account-wide value.
    browser = _max_datapoint(
        cloudwatch,
        _BROWSER_DIM,
        window_start,
        _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=1),
    )
    assert browser < observed, (
        f"{_METRIC_NAMESPACE}/{_METRIC_NAME} for Service=AgentCore.Browser reported {browser!r} "
        f"in the same window in which {_SESSIONS} CODE INTERPRETER sessions peaked at "
        f"{observed!r} and no browser session was started. The Service dimension is not "
        "partitioning the count"
    )


def _datapoints(cloudwatch, dimensions, start, end) -> list[dict]:
    """Maximum-statistic datapoints for one ActiveSessionCount series, newest first.

    An empty result makes the absence assertions pass and the presence assertions fail.
    """
    resp = cloudwatch.get_metric_statistics(
        Namespace=_METRIC_NAMESPACE,
        MetricName=_METRIC_NAME,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end,
        Period=60,
        Statistics=["Maximum"],
    )
    return sorted(resp.get("Datapoints", []), key=lambda d: d["Timestamp"], reverse=True)


def _max_datapoint(cloudwatch, dimensions, start, end) -> float:
    return max(
        (float(d["Maximum"]) for d in _datapoints(cloudwatch, dimensions, start, end)),
        default=0.0,
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout and never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
