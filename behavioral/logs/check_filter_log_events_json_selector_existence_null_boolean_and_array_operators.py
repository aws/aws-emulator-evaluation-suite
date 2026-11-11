"""filter-log-events-json-selector-existence-null-boolean-and-array-operators."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-log-events-json-selector-existence-null-boolean-and-array-operators"
GROUP = "log-events"
SERVICES = ["logs"]

#: Five JSON events named by their "m" member: a boolean vs the string "true", an explicit null vs
#: an absent member, and arrays and an object for the index and non-scalar comparisons.
_EVENTS = [
    {"m": "t-true", "flag": True, "opt": None, "arr": ["red", "blue"], "obj": {"k": 1}, "n": 1},
    {"m": "t-false", "flag": False, "arr": ["blue"], "obj": {"k": 2}, "n": 2},
    {"m": "t-null", "flag": None, "opt": "x", "arr": [], "n": 3},
    {"m": "t-absent", "arr": ["green", "red"], "n": 4},
    {"m": "t-strtrue", "flag": "true", "n": 5},
]

#: (filterPattern, the exact set of events it selects)
_CASES = [
    ("{$.flag IS TRUE}", {"t-true"}),
    ("{$.flag IS FALSE}", {"t-false"}),
    ("{$.flag IS NULL}", {"t-null"}),
    ("{$.opt IS NULL}", {"t-true"}),
    ("{$.flag NOT EXISTS}", {"t-absent"}),
    ("{$.opt NOT EXISTS}", {"t-absent", "t-false", "t-strtrue"}),
    ("{$.flag = true}", {"t-strtrue"}),
    ('{$.arr[0] = "red"}', {"t-true"}),
    ('{$.arr[1] = "red"}', {"t-absent"}),
    ('{$.arr[*] = "red"}', {"t-absent", "t-true"}),
    ('{$.arr[0] = "blue" || $.n = 4}', {"t-absent", "t-false"}),
    ('{$.m = "t-n*" || $.arr[1] = "red"}', {"t-absent", "t-null"}),
    ("{$.obj.k = 2 || $.flag IS NULL}", {"t-false", "t-null"}),
    ("{$.n != 1}", {"t-absent", "t-false", "t-null", "t-strtrue"}),
    ("{$.obj != 1}", set()),
    ('{$.arr != "red"}', set()),
    ("{$.missing != 1}", set()),
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


def _filter(logs, group: str, pattern: str) -> list[str]:
    kwargs = {"logGroupName": group, "filterPattern": pattern}
    names = []
    while True:
        page = logs.filter_log_events(**kwargs)
        names.extend(json.loads(e["message"])["m"] for e in page.get("events", []))
        token = page.get("nextToken")
        if not token:
            return names
        kwargs["nextToken"] = token


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents and TestMetricFilter select exactly the documented events for each JSON operator: IS
    TRUE/FALSE, IS NULL, NOT EXISTS, `= true` as a string, `[N]` and `[*]` indexing, `||`, and `!=` against
    an object, array or absent member (no match), with no duplicates.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-jsonops-")
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
    every = {e["m"] for e in _EVENTS}
    deadline = time.monotonic() + 90
    seen = set()
    while time.monotonic() < deadline:
        seen = set(_filter(logs, group, ""))
        if seen == every:
            break
        time.sleep(2)
    assert seen == every, f"the five written events never became filterable; saw {sorted(seen)!r}"

    filter_mismatch = {}
    test_mismatch = {}
    for pattern, expected in _CASES:
        got = _filter(logs, group, pattern)
        assert len(got) == len(set(got)), f"FilterLogEvents({pattern!r}) returned duplicates: {got!r}"
        if set(got) != expected:
            filter_mismatch[pattern] = {"expected": sorted(expected), "got": sorted(got)}
        matches = logs.test_metric_filter(filterPattern=pattern, logEventMessages=messages)["matches"]
        tested = {json.loads(mt["eventMessage"])["m"] for mt in matches}
        if tested != expected:
            test_mismatch[pattern] = {"expected": sorted(expected), "got": sorted(tested)}

    assert not filter_mismatch, f"FilterLogEvents selected the wrong events: {filter_mismatch!r}"
    assert not test_mismatch, (
        f"TestMetricFilter disagrees with the documented selection: {test_mismatch!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
