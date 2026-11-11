"""logs-insights-semantics-fields-rename-and-reserved-fields."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-fields-rename-and-reserved-fields"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _run_query(svc, groups, start_s, end_s, query, *, timeout_s=120, interval_s=1.0):
    qid = svc.start_query(
        logGroupNames=groups, startTime=start_s, endTime=end_s, queryString=query
    )["queryId"]
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            resp["queryId"] = qid
            return resp
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} ({query!r}) still {resp['status']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _rows(resp, *, drop=("@ptr",)):
    return [{f["field"]: f["value"] for f in row if f["field"] not in drop} for row in resp["results"]]


def _query_until(svc, groups, start_s, end_s, query, predicate, *, what, budget_s=180):
    """Ingestion is eventually consistent: re-run the query until its rows satisfy
    ``predicate`` or the budget is spent. Asserts content, never latency."""
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        resp = _run_query(svc, groups, start_s, end_s, query)
        if resp["status"] == "Complete" and predicate(resp):
            return resp
        last = (resp["status"], _rows(resp, drop=()), resp.get("statistics"))
        if time.monotonic() > deadline:
            raise AssertionError(f"{what}: {query!r} never satisfied the expectation in {budget_s}s; last={last!r}")
        time.sleep(3)


def _put(svc, group, stream, events):
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=sorted(events, key=lambda e: e["timestamp"]),
    )


def _fmt_ts(ms):
    dt = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{ms % 1000:03d}"


def _parse_ts(text):
    dt = datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
    return int(round(dt.timestamp() * 1000))


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """`fields` renames a field and drops the old name; @timestamp, @logStream and @log match what was
    written, @ptr is set, and @ingestionTime is no earlier than the event and near the PutLogEvents call.
    """
    svc = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    group = ctx.unique_name("sim2real-lisem-fields-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    # Non-round milliseconds so a target that truncates to seconds is caught.
    base = (int(time.time() * 1000) // 1000 - 300) * 1000
    ts = [base + 1234, base + 2345, base + 3456]
    msg_a0 = json.dumps({"id": "a-0", "level": "INFO"})
    msg_a1 = json.dumps({"id": "a-1", "level": "ERROR"})
    msg_b0 = "plain text line with no json fields"
    put_start_ms = int(time.time() * 1000)
    _put(svc, group, "stream-a", [{"timestamp": ts[0], "message": msg_a0},
                                  {"timestamp": ts[2], "message": msg_a1}])
    _put(svc, group, "stream-b", [{"timestamp": ts[1], "message": msg_b0}])
    put_end_ms = int(time.time() * 1000)

    start_s, end_s = base // 1000 - 60, put_end_ms // 1000 + 60
    query = ("fields @timestamp, @message, @logStream, @log, @ingestionTime, id as ident"
             " | sort @timestamp asc")
    resp = _query_until(svc, [group], start_s, end_s, query,
                        lambda r: len(r["results"]) == 3, what="all 3 planted events visible")
    raw = [{f["field"]: f["value"] for f in row} for row in resp["results"]]

    expected = [
        {"@timestamp": _fmt_ts(ts[0]), "@message": msg_a0, "@logStream": "stream-a",
         "@log": f"{account}:{group}", "ident": "a-0"},
        {"@timestamp": _fmt_ts(ts[1]), "@message": msg_b0, "@logStream": "stream-b",
         "@log": f"{account}:{group}"},
        {"@timestamp": _fmt_ts(ts[2]), "@message": msg_a1, "@logStream": "stream-a",
         "@log": f"{account}:{group}", "ident": "a-1"},
    ]
    got = [{k: v for k, v in r.items() if k not in ("@ptr", "@ingestionTime")} for r in raw]
    assert got == expected, f"projected rows differ from what was written:\n got={got!r}\nwant={expected!r}"

    for row in raw:
        assert "id" not in row, f"`id as ident` must not also project the source name `id`: {row!r}"
        assert row.get("@ptr"), f"every non-aggregate row carries a non-empty @ptr: {row!r}"
        assert "@ingestionTime" in row, f"@ingestionTime was requested but is absent: {row!r}"
        ing = _parse_ts(row["@ingestionTime"])
        ev = _parse_ts(row["@timestamp"])
        assert ing >= ev, f"@ingestionTime {row['@ingestionTime']!r} precedes @timestamp {row['@timestamp']!r}"
        # Server receipt time must fall around the PutLogEvents calls (5 min clock-skew allowance).
        assert put_start_ms - 300_000 <= ing <= put_end_ms + 300_000, (
            f"@ingestionTime {row['@ingestionTime']!r} is not a receipt time near the put window "
            f"[{_fmt_ts(put_start_ms)}, {_fmt_ts(put_end_ms)}]"
        )

    # Two events written by the same PutLogEvents call share one ingestion time.
    by_stream = {}
    for row in raw:
        by_stream.setdefault(row["@logStream"], set()).add(row["@ingestionTime"])
    assert len(by_stream["stream-a"]) == 1, (
        f"events from one PutLogEvents batch must share @ingestionTime, got {by_stream['stream-a']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
