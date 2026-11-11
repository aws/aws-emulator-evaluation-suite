"""deep-logs-1-logsql-sql-ppl-across-standard-and-infrequent-access-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-1-logsql-sql-ppl-across-standard-and-infrequent-access-rejected"
GROUP = 'insights'
SERVICES = ['logs']


_RANK = {"Scheduled": 0, "Running": 1, "Complete": 2}


def _await(svc, qid, *, timeout_s=120):
    """Poll GetQueryResults until Complete; any other terminal status, or a status moving
    backwards, fails the check."""
    seen = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        status = resp["status"]
        if not seen or seen[-1] != status:
            seen.append(status)
        if status not in ("Scheduled", "Running"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} still {status!r} after {timeout_s}s (trajectory {seen!r})")
        time.sleep(0.5)
    assert seen[-1] == "Complete", (
        f"query {qid} ended {seen[-1]!r} (trajectory {seen!r}); a non-Complete query is never a result"
    )
    assert all(s in _RANK for s in seen), f"query {qid} reported a status outside the state machine: {seen!r}"
    ranks = [_RANK[s] for s in seen]
    assert ranks == sorted(ranks), f"query {qid} status moved backwards: {seen!r}"
    return resp, seen


def _rows(resp):
    return [{f["field"]: f["value"] for f in row if f["field"] != "@ptr"} for row in resp["results"]]


def _query_until_scanned(svc, window, n_events, *, what, budget_s=240, **kw):
    """Re-run the query until it has scanned every planted event (ingestion into the
    Insights index is eventually consistent, and a fresh group's first queries scan 0)."""
    deadline = time.monotonic() + budget_s
    while True:
        qid = svc.start_query(startTime=window[0], endTime=int(time.time()) + 60, **kw)["queryId"]
        resp, seen = _await(svc, qid)
        scanned = resp.get("statistics", {}).get("recordsScanned")
        if scanned == float(n_events):
            return resp, seen
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{what}: scanned {scanned!r} of {n_events} planted events after {budget_s}s; rows={_rows(resp)!r}"
            )
        time.sleep(3)


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


def _recorded_with(svc, marker):
    out = []
    for page in svc.get_paginator("describe_queries").paginate():
        out += [q.get("queryString", "") for q in page["queries"] if marker in q.get("queryString", "")]
    return out
def _java_sdk_wrapped(text, code, msg):
    """The message as CloudWatch Logs relays it from its query backend: ``text`` followed by
    the backend's error envelope. The backend's Request ID is per call, so it is lifted from
    ``msg``; every other byte is graded."""
    rid = msg.rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
            f"Request ID: {rid}; Proxy: null)")


def _plant(svc, group, marker, planted, base):
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    put = svc.put_log_events(logGroupName=group, logStreamName="s", logEvents=[
        {"timestamp": base + i * 1000, "message": json.dumps({"svc": s, "ms": ms, "run": marker})}
        for i, (s, ms) in enumerate(planted)])
    assert not put.get("rejectedLogEventsInfo"), f"planted events were rejected in {group}: {put!r}"


_SAME_CLASS = "Querying is supported only in the same log class."


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """SQL and PPL over a STANDARD and an INFREQUENT_ACCESS log group together are refused
    InvalidParameterException and record no query; each group alone is accepted, so the refusal
    is the log-class mix, not either group or the dialect."""
    svc = ctx.client("logs")
    std = ctx.unique_name("sim2real-logsql-std-")
    ia = ctx.unique_name("sim2real-logsql-ia-")
    svc.create_log_group(logGroupName=std)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=std))
    svc.create_log_group(logGroupName=ia, logGroupClass="INFREQUENT_ACCESS")
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=ia))
    classes = {g["logGroupName"]: g.get("logGroupClass")
               for name in (std, ia)
               for g in svc.describe_log_groups(logGroupNamePrefix=name)["logGroups"] if g["logGroupName"] == name}
    assert classes == {std: "STANDARD", ia: "INFREQUENT_ACCESS"}, f"log classes as created: {classes!r}"

    marker = ctx.unique_name("mk").replace("-", "")
    base = int(time.time() * 1000) - 180_000
    planted = [("api", 1), ("api", 2), ("db", 3)]
    _plant(svc, std, marker, planted, base)
    _plant(svc, ia, marker, planted, base)
    window = (base // 1000 - 60,)

    # Break 1: SQL naming both classes in FROM.
    sql_mixed = (f"SELECT COUNT(*) AS n FROM `logGroups(logGroupIdentifier: ['{std}', '{ia}'])` "
                 f"WHERE run = '{marker}'")
    code, msg = _start_error(svc, queryLanguage="SQL", queryString=sql_mixed,
                             startTime=window[0], endTime=int(time.time()) + 60)
    assert code == "InvalidParameterException", f"SQL mixed class: expected InvalidParameterException, got {code!r} {msg!r}"
    assert msg == _java_sdk_wrapped(_SAME_CLASS, "InvalidParameterException", msg), (
        f"SQL mixed class: message must name the log-class rule, got {msg!r}"
    )

    # Break 2: PPL over both classes via logGroupNames.
    ppl_mixed = f"where run = '{marker}' | stats count() as n"
    code2, msg2 = _start_error(svc, queryLanguage="PPL", queryString=ppl_mixed, logGroupNames=[std, ia],
                               startTime=window[0], endTime=int(time.time()) + 60)
    assert code2 == "InvalidParameterException", f"PPL mixed class: expected InvalidParameterException, got {code2!r} {msg2!r}"
    assert msg2 == _java_sdk_wrapped(_SAME_CLASS, "InvalidParameterException", msg2), (
        f"PPL mixed class: message must name the log-class rule, got {msg2!r}"
    )

    recorded = _recorded_with(svc, marker)
    assert recorded == [], f"a refused StartQuery still recorded a query: {recorded!r}"

    # Positive control 1: SQL over the STANDARD group alone, exact count.
    sql_std = f"SELECT COUNT(*) AS n FROM `{std}` WHERE run = '{marker}'"
    resp, _ = _query_until_scanned(svc, window, len(planted), what="SQL standard-only",
                                   queryLanguage="SQL", queryString=sql_std)
    assert _rows(resp) == [{"n": str(len(planted))}], f"SQL standard-only returned {_rows(resp)!r}"

    # Positive control 2: PPL over the STANDARD group alone, exact count.
    resp_p, _ = _query_until_scanned(svc, window, len(planted), what="PPL standard-only",
                                     queryLanguage="PPL", queryString=ppl_mixed, logGroupNames=[std])
    assert _rows(resp_p) == [{"n": str(len(planted))}], f"PPL standard-only returned {_rows(resp_p)!r}"

    # Positive control 3: SQL over the INFREQUENT_ACCESS group alone is accepted and completes.
    qid = svc.start_query(queryLanguage="SQL", queryString=f"SELECT COUNT(*) AS n FROM `{ia}` WHERE run = '{marker}'",
                          startTime=window[0], endTime=int(time.time()) + 60)["queryId"]
    _, seen = _await(svc, qid)
    assert seen[-1] == "Complete", f"SQL over INFREQUENT_ACCESS alone must be accepted and Complete, saw {seen!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
