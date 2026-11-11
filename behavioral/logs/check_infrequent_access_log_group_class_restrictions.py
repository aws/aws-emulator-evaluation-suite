"""infrequent-access-log-group-class-restrictions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "infrequent-access-log-group-class-restrictions"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']


def _now_ms() -> int:
    return int(time.time() * 1000)


def _error(fn):
    """Call fn() and return its ClientError code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_log_group(svc, name):
    desc = svc.describe_log_groups(logGroupNamePrefix=name)
    for g in desc.get("logGroups", []):
        if g["logGroupName"] == name:
            return g
    raise AssertionError(f"log group {name!r} not found via DescribeLogGroups: {desc!r}")


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c6", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An INFREQUENT_ACCESS log group refuses metric filters, Live Tail and direct event reads that
    a STANDARD twin serves, yet still ingests events readable through Logs Insights.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html
    """
    svc = ctx.client("logs")

    ia_group = ctx.unique_name("sim2real-behav-lg-ia-")
    std_group = ctx.unique_name("sim2real-behav-lg-std-")
    svc.create_log_group(
        logGroupName=ia_group,
        logGroupClass="INFREQUENT_ACCESS",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda _n=ia_group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_group(
        logGroupName=std_group,
        logGroupClass="STANDARD",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda _n=std_group: svc.delete_log_group(logGroupName=_n))

    ia_desc = _describe_log_group(svc, ia_group)
    assert ia_desc.get("logGroupClass") == "INFREQUENT_ACCESS", (
        "DescribeLogGroups must report the class the group was created with, got "
        f"{ia_desc.get('logGroupClass')!r} for {ia_group!r}"
    )
    std_desc = _describe_log_group(svc, std_group)
    assert std_desc.get("logGroupClass") == "STANDARD", (
        f"expected STANDARD for the control group, got {std_desc.get('logGroupClass')!r}"
    )

    metric_transformations = [
        {
            "metricName": "IaClassProbe",
            "metricNamespace": ctx.unique_name("sim2real-behav-ia-ns-"),
            "metricValue": "1",
        }
    ]

    # Real AWS refuses with ValidationException here, not the modelled InvalidOperationException.
    ia_filter = ctx.unique_name("sim2real-behav-mf-ia-")
    ia_code, ia_message = _error(
        lambda: svc.put_metric_filter(
            logGroupName=ia_group,
            filterName=ia_filter,
            filterPattern="ERROR",
            metricTransformations=metric_transformations,
        )
    )
    assert ia_code == "ValidationException", (
        "PutMetricFilter on an INFREQUENT_ACCESS log group must be refused with "
        f"ValidationException, got {ia_code!r}"
    )
    expected_message = "This operation is only supported on the Standard log class."
    assert ia_message == expected_message, (
        f"expected message {expected_message!r}, got {ia_message!r}"
    )
    # Group-scoped DescribeMetricFilters is itself refused on IA, so absence is checked by name.
    ia_describe_code, ia_describe_message = _error(
        lambda: svc.describe_metric_filters(logGroupName=ia_group)
    )
    assert ia_describe_code == "ValidationException", (
        "DescribeMetricFilters scoped to an INFREQUENT_ACCESS log group must also be refused "
        f"with ValidationException (the class restriction covers the read path), got "
        f"{ia_describe_code!r}"
    )
    expected_message = "This operation is only supported on the Standard log class."
    assert ia_describe_message == expected_message, (
        f"expected message {expected_message!r}, got {ia_describe_message!r}"
    )
    ia_filters = svc.describe_metric_filters(filterNamePrefix=ia_filter)
    assert ia_filters.get("metricFilters", []) == [], (
        f"a refused PutMetricFilter must not create a filter: {ia_filters!r}"
    )

    std_filter = ctx.unique_name("sim2real-behav-mf-std-")
    svc.put_metric_filter(
        logGroupName=std_group,
        filterName=std_filter,
        filterPattern="ERROR",
        metricTransformations=metric_transformations,
    )
    std_filters = svc.describe_metric_filters(logGroupName=std_group)
    assert [f["filterName"] for f in std_filters.get("metricFilters", [])] == [std_filter], (
        "the identical PutMetricFilter must succeed on a STANDARD group -- the log group "
        f"class is the only difference; got {std_filters!r}"
    )

    # StartLiveTail refuses with InvalidParameterException: the code differs per operation.
    ia_arn = ia_desc["logGroupArn"]
    std_arn = std_desc["logGroupArn"]
    ia_tail_code, ia_tail_message = _error(lambda: svc.start_live_tail(logGroupIdentifiers=[ia_arn]))
    assert ia_tail_code == "InvalidParameterException", (
        "StartLiveTail on an INFREQUENT_ACCESS log group must be refused with "
        f"InvalidParameterException, got {ia_tail_code!r}"
    )
    expected_message = "This operation is only supported on the Standard log class."
    assert ia_tail_message == expected_message, (
        f"expected message {expected_message!r}, got {ia_tail_message!r}"
    )
    std_tail_code = None
    try:
        std_tail = svc.start_live_tail(logGroupIdentifiers=[std_arn])
    except ClientError as exc:
        std_tail_code = exc.response.get("Error", {}).get("Code")
    else:
        stream = std_tail.get("responseStream")
        if stream is not None:
            stream.close()
    # Not asserted to be None: concurrent Live Tail sessions are quota-limited per account.
    assert std_tail_code != "InvalidParameterException", (
        "StartLiveTail must NOT report a class restriction for a STANDARD log group -- "
        "InvalidParameterException here means the class check is inverted or "
        "unconditional"
    )

    ia_stream = ctx.unique_name("sim2real-behav-stream-ia-")
    svc.create_log_stream(logGroupName=ia_group, logStreamName=ia_stream)
    svc.put_log_events(
        logGroupName=ia_group,
        logStreamName=ia_stream,
        logEvents=[{"timestamp": _now_ms(), "message": "ia-class-ingest-works"}],
    )
    std_stream = ctx.unique_name("sim2real-behav-stream-std-")
    svc.create_log_stream(logGroupName=std_group, logStreamName=std_stream)
    svc.put_log_events(
        logGroupName=std_group,
        logStreamName=std_stream,
        logEvents=[{"timestamp": _now_ms(), "message": "std-class-ingest-works"}],
    )
    ia_filter_code, ia_filter_message = _error(
        lambda: svc.filter_log_events(
            logGroupName=ia_group, filterPattern="ia-class-ingest-works"
        )
    )
    assert ia_filter_code == "ValidationException", (
        "FilterLogEvents on an INFREQUENT_ACCESS log group must be refused with "
        f"ValidationException, got {ia_filter_code!r}"
    )
    expected_message = "This operation is only supported on the Standard log class."
    assert ia_filter_message == expected_message, (
        f"expected message {expected_message!r}, got {ia_filter_message!r}"
    )
    ia_get_code, ia_get_message = _error(
        lambda: svc.get_log_events(logGroupName=ia_group, logStreamName=ia_stream)
    )
    assert ia_get_code == "ValidationException", (
        "GetLogEvents on an INFREQUENT_ACCESS log group must be refused with "
        f"ValidationException, got {ia_get_code!r}"
    )
    expected_message = "This operation is only supported on the Standard log class."
    assert ia_get_message == expected_message, (
        f"expected message {expected_message!r}, got {ia_get_message!r}"
    )
    # PutLogEvents records become readable after a short delay, hence bounded polls.
    std_get_events = _poll_until(
        lambda: [
            e["message"]
            for e in svc.get_log_events(
                logGroupName=std_group, logStreamName=std_stream
            ).get("events", [])
        ],
        lambda msgs: msgs == ["std-class-ingest-works"],
        timeout_s=120,
        interval_s=2.0,
        description=(
            "GetLogEvents serves the STANDARD group's real event -- without this "
            "control, a target that unconditionally refuses GetLogEvents (a real bug, "
            "not class enforcement) would pass the IA-refusal assertion above unopposed"
        ),
    )
    assert std_get_events == ["std-class-ingest-works"], std_get_events
    # Unfiltered: a hyphenated literal term is not a reliable FilterLogEvents match.
    std_filter_events = _poll_until(
        lambda: [
            e["message"] for e in svc.filter_log_events(logGroupName=std_group).get("events", [])
        ],
        lambda msgs: msgs == ["std-class-ingest-works"],
        timeout_s=60,
        interval_s=2.0,
        description="FilterLogEvents serves the STANDARD group's real event",
    )
    assert std_filter_events == ["std-class-ingest-works"], std_filter_events

    # On IA, an event can take around two minutes to become queryable in Logs Insights.
    ia_streams = _poll_until(
        lambda: svc.describe_log_streams(
            logGroupName=ia_group, logStreamNamePrefix=ia_stream
        ).get("logStreams", []),
        lambda ss: bool(ss) and ss[0].get("lastIngestionTime") is not None,
        timeout_s=120,
        interval_s=5.0,
        description="the IA log group accepted the event (DescribeLogStreams reports ingestion)",
    )
    assert ia_streams[0]["logStreamName"] == ia_stream, ia_streams

    def _insights():
        query = svc.start_query(
            logGroupName=ia_group,
            startTime=int(_now_ms() / 1000) - 900,
            endTime=int(_now_ms() / 1000) + 60,
            queryString="fields @message | limit 10",
        )
        results = _poll_until(
            lambda: svc.get_query_results(queryId=query["queryId"]),
            lambda r: r.get("status") in {"Complete", "Failed", "Cancelled"},
            timeout_s=60,
            interval_s=2.0,
            description="Logs Insights query reaches a terminal status",
        )
        assert results["status"] == "Complete", results
        return [
            f["value"]
            for row in results.get("results", [])
            for f in row
            if f["field"] == "@message"
        ]

    ia_events = _poll_until(
        _insights,
        lambda msgs: msgs == ["ia-class-ingest-works"],
        timeout_s=240,
        interval_s=10.0,
        description="the IA log group's event is readable through Logs Insights",
    )
    assert ia_events == ["ia-class-ingest-works"], (
        "INFREQUENT_ACCESS must still support ingestion + a Logs Insights read, got "
        f"{ia_events!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
