"""logs-insights-get-query-results-paginates-cwli-results-into-disjoint-pages."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-get-query-results-paginates-cwli-results-into-disjoint-pages"
GROUP = "insights"
SERVICES = ["logs"]


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")
_QUERY = "fields n | sort n asc"
_FOREIGN_TOKEN = (
    "InvalidParameterException",
    "Invalid token for query (Service: AWSLogs; Status Code: 400; "
    "Error Code: InvalidParameterException; Request ID: <id>; Proxy: null)",
)
_MAX_ITEMS_TOO_LARGE = (
    "InvalidParameterException",
    "1 validation error detected: Value at 'maxItems' failed to satisfy constraint: "
    "Member must have value less than or equal to 10000",
)


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _delete_group(svc, group):
    try:
        svc.delete_log_group(logGroupName=group)
    except svc.exceptions.ResourceNotFoundException:
        pass


def expect_error(fn, code, message):
    """Assert fn() is refused with exactly (code, message); `<id>` in message stands for the per-call
    request id CloudWatch Logs appends, read from the refusal only in its 36-character form."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
    else:
        raise AssertionError(
            f"expected {code!r} {message!r}, but the call SUCCEEDED and returned {result!r}"
        )
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", got[1] or "")
    want = (code, message.replace("<id>", found.group(1) if found else "<no request id>"))
    assert got == want, f"expected {want!r}, got {got!r}"


def _query(ctx, svc, group, window, query, deadline=None):
    """Start `query`, poll it to a terminal status, which must be Complete; return (queryId, response)."""
    qid = svc.start_query(
        logGroupName=group, startTime=window[0], endTime=window[1], queryString=query
    )["queryId"]
    stop = time.monotonic() + _budget(ctx, 60)
    stop = stop if deadline is None else min(stop, deadline)
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            assert resp["status"] == "Complete", f"{query!r} ended {resp['status']!r}: {resp!r}"
            return qid, resp
        if time.monotonic() > stop:
            raise AssertionError(f"{query!r} ({qid}) never reached a terminal status: {resp!r}")
        time.sleep(1)


def _query_until(ctx, svc, group, window, query, matched, *, cap_s=240, reserve_s=30):
    """Re-run `query` every 3 s until recordsMatched equals `matched`: ingestion into a new group is
    eventually consistent. Only that final terminal response is returned and graded."""
    deadline = time.monotonic() + _budget(ctx, cap_s, reserve_s)
    while True:
        qid, resp = _query(ctx, svc, group, window, query, deadline)
        if resp["statistics"]["recordsMatched"] == float(matched):
            return qid, resp
        left = deadline - time.monotonic()
        if left <= 0:
            raise AssertionError(
                f"{query!r} never matched {matched} records: {resp['statistics']!r}"
            )
        time.sleep(min(3.0, left))


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetQueryResults with maxItems splits a finished query's rows into disjoint pages that concatenate
    to the unpaged result, each with the full statistics; a token replays, a token from another query
    is refused, and maxItems above 10000 is refused.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-gqr-pages-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: _delete_group(svc, group))
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    # Events stamped before the group existed are never visible to Insights.
    t0_s = int(time.time()) + 1
    svc.put_log_events(
        logGroupName=group,
        logStreamName="s",
        logEvents=[
            {"timestamp": (t0_s + i) * 1000, "message": json.dumps({"n": i})} for i in range(12)
        ],
    )
    window = (t0_s - 60, t0_s + 600)

    qid, full = _query_until(ctx, svc, group, window, _QUERY, 12)
    values = [row[0]["value"] for row in full["results"]]
    assert values == [str(i) for i in range(12)], (
        f"unpaged {_QUERY!r} returned n {values!r}, expected 0..11"
    )
    assert "nextToken" not in full, (
        f"unpaged {_QUERY!r} returned a nextToken: {full['nextToken']!r}"
    )

    pages, token = [], None
    while len(pages) < 4:
        page = svc.get_query_results(
            queryId=qid, maxItems=5, **({"nextToken": token} if token else {})
        )
        pages.append(page)
        token = page.get("nextToken")
        if not token:
            break
    sizes = [len(p["results"]) for p in pages]
    assert sizes == [5, 5, 2], (
        f"maxItems=5 pages held {sizes!r} rows, expected [5, 5, 2] ending without a token"
    )
    assert "nextToken" not in pages[-1], (
        f"the last maxItems=5 page carries nextToken {pages[-1]['nextToken']!r}"
    )
    joined = [row for p in pages for row in p["results"]]
    assert joined == full["results"], (
        f"the maxItems=5 pages concatenate to {joined!r}, not the unpaged rows"
    )
    for i, page in enumerate(pages):
        assert page["status"] == "Complete" and page["statistics"] == full["statistics"], (
            f"page {i} reports {page['status']!r} {page['statistics']!r}, expected the unpaged {full['statistics']!r}"
        )

    first_token = pages[0]["nextToken"]
    replay = svc.get_query_results(queryId=qid, maxItems=5, nextToken=first_token)
    assert replay["results"] == pages[1]["results"], (
        f"replaying the first page's token returned {replay['results']!r}, expected the second page again"
    )

    other_qid, _ = _query(ctx, svc, group, window, _QUERY)
    expect_error(
        lambda: svc.get_query_results(queryId=other_qid, maxItems=5, nextToken=first_token),
        *_FOREIGN_TOKEN,
    )

    expect_error(lambda: svc.get_query_results(queryId=qid, maxItems=10001), *_MAX_ITEMS_TOO_LARGE)
    at_cap = svc.get_query_results(queryId=qid, maxItems=10000)
    assert at_cap["results"] == full["results"] and "nextToken" not in at_cap, (
        f"maxItems=10000 returned {at_cap['results']!r} {at_cap.get('nextToken')!r}, expected the unpaged rows"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
