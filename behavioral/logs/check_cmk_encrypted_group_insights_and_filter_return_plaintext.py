"""cmk-encrypted-group-insights-and-filter-return-plaintext."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cmk-encrypted-group-insights-and-filter-return-plaintext"
GROUP = "kms-encryption-context"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Over a CMK-encrypted log group, FilterLogEvents returns exactly the matching events and a
    Logs Insights filter/parse/stats query computes over the plaintext; expected rows come from
    the seeded events."""
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-logs-cmkq-")
    stream = ctx.unique_name("sim2real-behav-logs-cmkq-s-")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AccountRootAdmin", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "LogsForThisGroup", "Effect": "Allow",
             "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
             "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                        "kms:GenerateDataKey*", "kms:Describe*"],
             "Resource": "*",
             "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn":
                 f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"}}},
        ],
    }
    key_arn = kms.create_key(Policy=json.dumps(policy), Description=f"sim2real {CHECK}",
                             Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    ctx.on_cleanup(lambda: _delete_group_if_present(logs, group))
    _create_with_retry(logs, group, key_arn)
    g = _describe_group(logs, group)
    assert g is not None and g.get("kmsKeyId") == key_arn, f"group not encrypted: {g!r}"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    base = int(time.time() * 1000) - 60_000
    seeded = [
        ("checkout", "ok", 120), ("checkout", "error", 900), ("search", "ok", 40),
        ("checkout", "ok", 180), ("search", "error", 700), ("search", "ok", 60),
    ]
    events = [{"timestamp": base + i * 1000,
               "message": f"route={r} outcome={o} latency_ms={lat}"}
              for i, (r, o, lat) in enumerate(seeded)]
    logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)

    want_errors = [e["message"] for e in events if "outcome=error" in e["message"]]
    errors = _poll(lambda: _filter(logs, group, '"outcome=error"'),
                   lambda got: len(got) >= len(want_errors), 90)
    assert errors == want_errors, (
        f"FilterLogEvents over the CMK group returned {errors!r}, expected {want_errors!r}"
    )

    query = ("fields @message | filter @message like /outcome=ok/ "
             "| parse @message 'route=* outcome=* latency_ms=*' as route, outcome, latency "
             "| stats count(*) as n, sum(latency) as total by route | sort route asc")
    expected = {}
    for r, o, lat in seeded:
        if o == "ok":
            n, t = expected.get(r, (0, 0))
            expected[r] = (n + 1, t + lat)
    want_rows = [{"route": r, "n": str(n), "total": str(t)} for r, (n, t) in sorted(expected.items())]

    def _run_query():
        qid = logs.start_query(logGroupName=group, startTime=base // 1000 - 60,
                               endTime=int(time.time()) + 60, queryString=query)["queryId"]
        deadline = time.monotonic() + 120
        while True:
            resp = logs.get_query_results(queryId=qid)
            if resp["status"] in {"Complete", "Failed", "Cancelled", "Timeout"}:
                return resp
            assert time.monotonic() < deadline, f"query {qid} still {resp['status']!r}"
            time.sleep(2)

    # Ingestion into the query index lags the write; re-run until the matched count settles.
    resp = _poll(_run_query, lambda r: r["status"] == "Complete" and _rows(r) == want_rows, 180,
                 interval_s=10)
    assert resp["status"] == "Complete", f"Insights query ended {resp['status']!r}"
    assert _rows(resp) == want_rows, (
        f"Insights over the CMK group returned {_rows(resp)!r}, expected {want_rows!r}"
    )


def _rows(resp: dict) -> list[dict]:
    return [{f["field"]: f["value"] for f in row if not f["field"].startswith("@")}
            for row in resp.get("results", [])]


def _filter(logs: Any, group: str, pattern: str) -> list[str]:
    out: list[str] = []
    for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, filterPattern=pattern):
        out.extend(e["message"] for e in page["events"])
    return out


def _poll(fn, cond, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not cond(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = fn()
    return last


def _create_with_retry(logs: Any, name: str, key_arn: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            logs.create_log_group(logGroupName=name, kmsKeyId=key_arn, tags={"sim2real": CHECK})
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"AccessDeniedException",
                                                     "InvalidParameterException"}:
                raise
            last = exc
            time.sleep(5)
    raise AssertionError(f"CreateLogGroup with the CMK never succeeded within {timeout_s}s: {last!r}")


def _describe_group(logs: Any, name: str) -> dict | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


def _delete_group_if_present(logs: Any, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
