"""metrics-from-logs-no-matching-line-emits-no-datapoint-and-an-empty-complete-query."""
from __future__ import annotations

import io
import json
import time
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-from-logs-no-matching-line-emits-no-datapoint-and-an-empty-complete-query"
GROUP = "metric-filter"
SERVICES = ["cloudwatch", "lambda", "logs"]

_LINES = [
    "HEARTBEAT node=a",
    "HEARTBEAT node=b",
    "HEARTBEAT node=c",
    # Near-misses of the absent term: filter patterns and Insights regexes are case-sensitive,
    # and neither of these contains the exact byte sequence CHECKSUM_MISMATCH.
    "checksum_mismatch node=a lowercase",
    "CHECKSUM MISMATCH node=b split",
]
_ABSENT = "CHECKSUM_MISMATCH"


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """For a term no Lambda line contains, the metric gets no datapoint, FilterLogEvents returns
    nothing and a Logs Insights stats count(*) finishes Complete with no rows, while a filter and
    query on a present term both count exactly 3."""
    group, fn = _emitter(ctx)
    logs = ctx.client("logs")
    namespace = ctx.unique_name("Sim2Real/MetricsFromLogs/")

    present = ctx.unique_name("sim2real-mfl-mf-hb-")
    logs.put_metric_filter(
        logGroupName=group, filterName=present, filterPattern='"HEARTBEAT"',
        metricTransformations=[{
            "metricName": "Heartbeats", "metricNamespace": namespace, "metricValue": "1",
        }],
    )
    ctx.on_cleanup(lambda: _delete_metric_filter(ctx, group, present))
    absent = ctx.unique_name("sim2real-mfl-mf-cm-")
    logs.put_metric_filter(
        logGroupName=group, filterName=absent, filterPattern=f'"{_ABSENT}"',
        metricTransformations=[{
            "metricName": "ChecksumMismatches", "metricNamespace": namespace, "metricValue": "1",
        }],
    )
    ctx.on_cleanup(lambda: _delete_metric_filter(ctx, group, absent))

    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    _emit(ctx, fn, _LINES)
    _wait_lines(ctx, group, _LINES)

    # --- positive control, both instruments
    hb = _poll_stats(
        ctx, namespace, "Heartbeats", [], since, lambda s: s["sum"] >= 3,
        description="HEARTBEAT control metric reaches 3",
    )
    assert hb["sum"] == 3.0, f"control metric Sum is {hb['sum']!r}, expected 3.0"
    hb_rows = _insights(
        ctx, group, "filter @message like /HEARTBEAT/ | stats count(*) as n",
        lambda rs: bool(rs) and int(rs[0].get("n", 0)) >= 3,
    )
    assert hb_rows == [{"n": "3"}], f"control Insights count returned {hb_rows!r}, expected n=3"

    # --- the absent term, now that the data is provably visible to both instruments
    fle = _fle_messages(ctx, group, f'"{_ABSENT}"')
    assert fle == [], f"FilterLogEvents for an absent term returned {fle!r}"

    final = _query_once(ctx, group, f"filter @message like /{_ABSENT}/ | stats count(*) as n")
    assert final["status"] == "Complete", (
        f"a query matching nothing must finish Complete, got {final['status']!r}: {final!r}"
    )
    assert final["results"] == [], (
        f"a stats count(*) over zero matches returns NO rows, got {final['results']!r}"
    )

    none = _stats(ctx, namespace, "ChecksumMismatches", [], since)
    assert none["points"] == [], (
        f"no line contains {_ABSENT!r}, yet its metric has datapoints {none['points']!r}"
    )


_HANDLER_SRC = '''
def handler(event, context):
    for line in event["lines"]:
        print(line)
    return {"printed": len(event["lines"])}
'''

_LAMBDA_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _zip_bytes(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
    except iam.exceptions.NoSuchEntityException:
        return
    iam.delete_role(RoleName=name)


def _delete_function(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    try:
        lam.delete_function(FunctionName=name)
    except lam.exceptions.ResourceNotFoundException:
        pass


def _delete_log_group(ctx, name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=name)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _delete_metric_filter(ctx, group: str, name: str) -> None:
    logs = ctx.client("logs")
    try:
        logs.delete_metric_filter(logGroupName=group, filterName=name)
    except logs.exceptions.ResourceNotFoundException:
        pass


def _emitter(ctx):
    """A log group this check owns, and a Lambda function whose stdout lands in it.

    The function logs to the pre-created group through LoggingConfig, and its role may only
    CreateLogStream/PutLogEvents on that one group -- no CreateLogGroup -- so a late flush after
    teardown cannot recreate the group and no /aws/lambda/<fn> group is ever made.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-mfl-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _delete_log_group(ctx, group))
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"

    role = ctx.unique_name("sim2real-mfl-role-")
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role))
    iam.put_role_policy(
        RoleName=role,
        PolicyName="write-own-log-group",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": [group_arn, f"{group_arn}:*"],
            }],
        }),
    )

    fn = ctx.unique_name("sim2real-mfl-fn-")
    kwargs = dict(
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_bytes(_HANDLER_SRC)},
        Timeout=15,
        MemorySize=128,
        LoggingConfig={"LogFormat": "Text", "LogGroup": group},
        Tags={"sim2real": CHECK},
    )
    # IAM propagation exposes no condition to poll; the bounded retry on the one error it
    # produces at first use is what makes this correct, the sleep only makes it cheaper.
    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            if "cannot be assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(4)
    ctx.on_cleanup(lambda: _delete_function(ctx, fn))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn).get("State"),
        lambda s: s in ("Active", "Failed"),
        timeout_s=120, interval_s=2, description=f"function {fn} leaves Pending",
    )
    state = lam.get_function_configuration(FunctionName=fn)
    assert state.get("State") == "Active", f"function {fn} is {state.get('State')!r}: {state!r}"
    return group, fn


def _emit(ctx, fn: str, lines) -> None:
    """Invoke the function synchronously; it prints each line to stdout, one log event each."""
    resp = ctx.client("lambda").invoke(
        FunctionName=fn, Payload=json.dumps({"lines": list(lines)}).encode()
    )
    body = json.loads(resp["Payload"].read())
    assert resp.get("FunctionError") is None, f"emitter raised: {body!r}"
    assert body == {"printed": len(lines)}, f"emitter printed {body!r}, expected {len(lines)} lines"


def _fle_messages(ctx, group: str, pattern: str | None = None) -> list:
    """Every message FilterLogEvents returns for the group (paginated), newline-stripped."""
    logs = ctx.client("logs")
    kwargs = {"logGroupName": group}
    if pattern is not None:
        kwargs["filterPattern"] = pattern
    out = []
    for page in logs.get_paginator("filter_log_events").paginate(**kwargs):
        out.extend(e["message"].rstrip("\n") for e in page.get("events", []))
    return out


def _wait_lines(ctx, group: str, lines) -> None:
    """Poll until every emitted line (with multiplicity) is readable back from the group."""
    want = Counter(lines)
    _poll_until(
        lambda: Counter(m for m in _fle_messages(ctx, group) if m in want),
        lambda have: have == want,
        timeout_s=90, interval_s=3, description=f"all {len(lines)} emitted lines readable",
    )


def _stats(ctx, namespace: str, metric: str, dimensions, since) -> dict:
    points = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=dimensions,
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=["Sum", "SampleCount", "Minimum", "Maximum"],
    ).get("Datapoints", [])
    return {
        "points": points,
        "sum": sum(p["Sum"] for p in points),
        "samples": sum(p["SampleCount"] for p in points),
        "min": min((p["Minimum"] for p in points), default=None),
        "max": max((p["Maximum"] for p in points), default=None),
    }


def _poll_stats(ctx, namespace, metric, dimensions, since, predicate, *, description, timeout_s=150):
    return _poll_until(
        lambda: _stats(ctx, namespace, metric, dimensions, since),
        predicate, timeout_s=timeout_s, interval_s=5, description=description,
    )


def _query_once(ctx, group: str, query: str) -> dict:
    """Run one Logs Insights query to a terminal status; rows come back as {field: value}."""
    logs = ctx.client("logs")
    now = int(time.time())
    qid = logs.start_query(
        logGroupName=group, startTime=now - 900, endTime=now + 300, queryString=query
    )["queryId"]
    res = _poll_until(
        lambda: logs.get_query_results(queryId=qid),
        lambda r: r.get("status") in ("Complete", "Failed", "Cancelled", "Timeout", "Unknown"),
        timeout_s=90, interval_s=2, description=f"query {qid} reaches a terminal status",
    )
    return {
        "status": res.get("status"),
        "results": [{f["field"]: f["value"] for f in row if f["field"] != "@ptr"}
                    for row in res.get("results", [])],
    }


def _insights(ctx, group: str, query: str, ready, *, timeout_s=150) -> list:
    """Re-run the query until it completes AND `ready(rows)` holds -- Insights visibility of
    freshly ingested events is eventually consistent -- then return the rows."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _query_once(ctx, group, query)
        if last["status"] == "Complete" and ready(last["results"]):
            return last["results"]
        time.sleep(5)
    raise AssertionError(f"query {query!r} never became ready within {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
