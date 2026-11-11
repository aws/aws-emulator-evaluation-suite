"""logs-insights-semantics-both-log-group-selectors-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-semantics-both-log-group-selectors-rejected"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _poll(svc, qid, *, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            return resp
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} still {resp['status']!r} after {timeout_s}s")
        time.sleep(1.0)


def _rows(resp, *, drop=("@ptr",)):
    return [{f["field"]: f["value"] for f in row if f["field"] not in drop} for row in resp["results"]]


def _start_error(svc, **kwargs):
    """The error StartQuery raised. A success is itself the finding, so it raises (after
    stopping the phantom query) rather than returning a sentinel that looks like a code."""
    try:
        resp = svc.start_query(**kwargs)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    try:
        svc.stop_query(queryId=resp["queryId"])
    except ClientError:
        pass
    raise AssertionError(f"StartQuery accepted a request real AWS refuses: {kwargs!r} -> {resp!r}")


def _described_strings(svc, group):
    out = []
    for page in svc.get_paginator("describe_queries").paginate(logGroupName=group):
        out += [q.get("queryString", "") for q in page["queries"]]
    return out


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery with both logGroupName and logGroupNames is refused with InvalidParameterException and
    its exact message and starts no query, while each selector alone returns the planted event.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-selectors-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    marker = ctx.unique_name("mk")
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    now_ms = int(time.time() * 1000)
    svc.put_log_events(logGroupName=group, logStreamName="s",
                       logEvents=[{"timestamp": now_ms - 60_000, "message": f"event {marker}"}])
    window = dict(startTime=now_ms // 1000 - 600, endTime=now_ms // 1000 + 60)
    query = f"fields @message | filter @message like '{marker}'"

    code, msg = _start_error(svc, logGroupName=group, logGroupNames=[group], queryString=query, **window)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    expected = "Both logGroupName and logGroupNames cannot be specified at the same time"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"
    phantom = [s for s in _described_strings(svc, group) if marker in s]
    assert not phantom, f"the refused StartQuery still created a query: {phantom!r}"

    # Positive controls: each selector on its own is accepted and sees the event.
    for label, sel in (("logGroupName", {"logGroupName": group}), ("logGroupNames", {"logGroupNames": [group]})):
        deadline = time.monotonic() + 180
        while True:
            resp = _poll(svc, svc.start_query(queryString=query, **sel, **window)["queryId"])
            if resp["status"] == "Complete" and len(resp["results"]) == 1:
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"{label} alone never returned the planted event: {resp!r}")
            time.sleep(3)
        assert _rows(resp) == [{"@message": f"event {marker}"}], f"{label} control rows {_rows(resp)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
