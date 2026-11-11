"""filter-log-events-bare-exists-selector-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-log-events-bare-exists-selector-rejected"
GROUP = "log-events"
SERVICES = ["logs"]

_EVENTS = [
    {"m": "has-flag", "flag": True},
    {"m": "no-flag", "other": 1},
]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _metric_filters(logs, group: str) -> list[str]:
    kwargs = {"logGroupName": group}
    names = []
    while True:
        page = logs.describe_metric_filters(**kwargs)
        names.extend(f["filterName"] for f in page.get("metricFilters", []))
        token = page.get("nextToken")
        if not token:
            return names
        kwargs["nextToken"] = token


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents, TestMetricFilter and PutMetricFilter refuse the bare selector `{$.flag EXISTS}` with
    InvalidParameterException and the exact message, and no filter is created, while `NOT EXISTS` is
    accepted by all three and selects exactly the event without the member.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-exists-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=group),
                             "ResourceNotFoundException"))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    messages = [json.dumps(e) for e in _EVENTS]
    base = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(messages)],
    )

    good = "{$.flag NOT EXISTS}"
    bad = "{$.flag EXISTS}"

    # Positive control: the negated operator is accepted everywhere and selects exactly no-flag.
    deadline = time.monotonic() + 90
    selected: list = []
    while time.monotonic() < deadline:
        selected = [json.loads(e["message"])["m"]
                    for e in logs.filter_log_events(logGroupName=group, filterPattern=good)["events"]]
        if selected:
            break
        time.sleep(2)
    assert selected == ["no-flag"], f"FilterLogEvents({good!r}) selected {selected!r}, expected ['no-flag']"
    tested = [json.loads(m["eventMessage"])["m"]
              for m in logs.test_metric_filter(filterPattern=good, logEventMessages=messages)["matches"]]
    assert tested == ["no-flag"], f"TestMetricFilter({good!r}) matched {tested!r}, expected ['no-flag']"
    good_filter = ctx.unique_name("sim2real-behav-mf-ok-")
    logs.put_metric_filter(
        logGroupName=group, filterName=good_filter, filterPattern=good,
        metricTransformations=[{"metricName": good_filter, "metricNamespace": "Sim2RealBehav/Logs",
                                "metricValue": "1"}],
    )
    ctx.on_cleanup(_teardown(lambda: logs.delete_metric_filter(logGroupName=group, filterName=good_filter),
                             "ResourceNotFoundException"))

    code, msg = _error(lambda: logs.filter_log_events(logGroupName=group, filterPattern=bad))
    assert (code, msg) == ("InvalidParameterException", "Invalid filter pattern"), (
        f"FilterLogEvents({bad!r}) was refused with {code!r} / {msg!r}"
    )
    code, msg = _error(lambda: logs.test_metric_filter(filterPattern=bad, logEventMessages=messages))
    assert (code, msg) == ("InvalidParameterException", "Invalid metric filter pattern"), (
        f"TestMetricFilter({bad!r}) was refused with {code!r} / {msg!r}"
    )
    bad_filter = ctx.unique_name("sim2real-behav-mf-bad-")
    code, msg = _error(lambda: logs.put_metric_filter(
        logGroupName=group, filterName=bad_filter, filterPattern=bad,
        metricTransformations=[{"metricName": bad_filter, "metricNamespace": "Sim2RealBehav/Logs",
                                "metricValue": "1"}],
    ))
    ctx.on_cleanup(_teardown(lambda: logs.delete_metric_filter(logGroupName=group, filterName=bad_filter),
                             "ResourceNotFoundException"))
    assert (code, msg) == ("InvalidParameterException", "Invalid metric filter pattern"), (
        f"PutMetricFilter({bad!r}) was refused with {code!r} / {msg!r}"
    )

    filters = sorted(_metric_filters(logs, group))
    assert filters == [good_filter], (
        f"after one accepted and one refused PutMetricFilter the group holds {len(filters)} filter(s); "
        "expected exactly the accepted one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
