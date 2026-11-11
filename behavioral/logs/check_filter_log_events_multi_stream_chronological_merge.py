"""filter-log-events-multi-stream-chronological-merge."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "filter-log-events-multi-stream-chronological-merge"
GROUP = "ordering"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents merges events from multiple log streams into true global
    chronological order (by timestamp), not per-stream concatenation order."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    stream_names = {
        "A": ctx.unique_name("sim2real-behav-streamA-"),
        "B": ctx.unique_name("sim2real-behav-streamB-"),
        "C": ctx.unique_name("sim2real-behav-streamC-"),
    }
    for sname in stream_names.values():
        logs.create_log_stream(logGroupName=group_name, logStreamName=sname)

    base = int(time.time() * 1000) - 3600_000  # 1h in the past, avoids "too new" rejection
    # Per-stream timestamps are individually increasing (required by PutLogEvents),
    # but interleaved across streams so the true chronological merge differs from
    # a simple per-stream concatenation.
    offsets = {
        "A": [0, 300, 600],
        "B": [100, 400, 900],
        "C": [200, 500, 700],
    }
    expected_order = []  # list of (stream_letter, index) in true chronological order
    all_events = []
    for letter, offs in offsets.items():
        for idx, off in enumerate(offs):
            all_events.append((letter, idx, base + off))
    all_events.sort(key=lambda e: e[2])
    expected_order = [(letter, idx) for letter, idx, _ts in all_events]
    # Sanity: this must NOT equal simple per-stream concatenation (A0,A1,A2,B0,B1,B2,C0,C1,C2)
    concatenation_order = [
        (letter, idx) for letter in ("A", "B", "C") for idx in range(len(offsets[letter]))
    ]
    assert expected_order != concatenation_order, "test fixture must be genuinely interleaved"

    for letter, offs in offsets.items():
        events = [
            {"timestamp": base + off, "message": f"stream{letter}-event{idx}"}
            for idx, off in enumerate(offs)
        ]
        logs.put_log_events(
            logGroupName=group_name, logStreamName=stream_names[letter], logEvents=events
        )

    total_expected = sum(len(v) for v in offsets.values())

    # Query with an explicit logStreamNames list and no startTime/endTime:
    # FilterLogEvents' default stream auto-discovery may not find freshly
    # created streams, and a time bound can zero the result for them.
    # This log group is freshly created under a unique name and holds only the
    # events this check writes, so an explicit-stream, time-unbounded query is
    # still exact.
    all_stream_names = list(stream_names.values())

    def _fetch_all():
        collected = []
        token = None
        while True:
            kwargs = {
                "logGroupName": group_name,
                "logStreamNames": all_stream_names,
                "startFromHead": True,
            }
            if token:
                kwargs["nextToken"] = token
            resp = logs.filter_log_events(**kwargs)
            collected.extend(resp.get("events", []))
            token = resp.get("nextToken")
            if not token:
                break
        return collected

    events = []
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        events = _fetch_all()
        if len(events) >= total_expected:
            break
        time.sleep(3.0)
    assert len(events) == total_expected, (
        f"expected {total_expected} events via FilterLogEvents, got {len(events)}"
    )

    # Derive (stream_letter, index) for each returned event from its message.
    stream_by_arn_stream_name = {v: k for k, v in stream_names.items()}
    observed_order = []
    for ev in events:
        msg = ev["message"]  # "stream{letter}-event{idx}"
        letter = msg[len("stream")]
        idx = int(msg.rsplit("event", 1)[1])
        observed_order.append((letter, idx))
        # cross-check against the logStreamName field too
        assert stream_by_arn_stream_name[ev["logStreamName"]] == letter, (
            f"message-derived stream {letter!r} disagrees with logStreamName "
            f"{ev['logStreamName']!r}"
        )

    # Timestamps must be globally non-decreasing across the merged, multi-stream result.
    timestamps = [ev["timestamp"] for ev in events]
    assert timestamps == sorted(timestamps), "FilterLogEvents result is not globally time-sorted"

    assert observed_order == expected_order, (
        f"expected true chronological merge {expected_order}, got {observed_order}"
    )
    assert observed_order != concatenation_order, (
        f"observed order {observed_order} matches naive per-stream concatenation "
        f"{concatenation_order}; the merge is not being exercised"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
