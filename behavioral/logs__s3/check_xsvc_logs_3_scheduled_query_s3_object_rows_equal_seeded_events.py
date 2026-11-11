"""xsvc-logs-3-scheduled-query-s3-object-rows-equal-seeded-events."""
from __future__ import annotations

import datetime
import json
import time
import uuid
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-logs-3-scheduled-query-s3-object-rows-equal-seeded-events"
GROUP = "scheduled-query-destination"
SERVICES = ["logs", "s3"]


# timing:real-time — schedule: 60 s
@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A scheduled Logs Insights query's S3 object holds exactly the seeded matching events (same
    messages, order and timestamps, no decoy), and GetScheduledQueryHistory records the run as
    Complete with an S3/COMPLETE destination whose processedIdentifier names that object.
    """
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    tag = uuid.uuid4().hex[:12]
    marker = f"sim2real-sqs3-{tag}"
    bucket = _make_bucket(ctx, s3, "sim2real-xsvc-sqs3-")
    prefix = "results"
    dest_uri = f"s3://{bucket}/{prefix}/"

    group = ctx.unique_name("sim2real-xsvc-sqs3-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = "seed"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    base = int(time.time() * 1000) - 10_000
    seeded = [{"timestamp": base + i, "message": f"{marker} row={i}"} for i in range(3)]
    decoy = {"timestamp": base + 3, "message": f"unrelated-{tag} row=decoy"}
    resp = logs.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=seeded + [decoy]
    )
    assert not resp.get("rejectedLogEventsInfo"), (
        f"seed events were rejected: {resp.get('rejectedLogEventsInfo')!r}"
    )
    query_string = (
        f"fields @timestamp, @message | filter @message like /{marker}/ | sort @timestamp asc"
    )
    # Barrier: the scheduled run can only be graded against the seed once Insights itself
    # returns all of it; otherwise a correct scheduler could serialize a partial result.
    _wait_insights_sees(logs, group, query_string, [e["message"] for e in seeded])

    role_name = ctx.unique_name("sim2real-xsvc-sqs3-role-")
    role_arn = _make_role(ctx, iam, role_name, bucket, s3_actions=["s3:PutObject"])

    query_name = ctx.unique_name("sim2real-xsvc-sqs3-q-")
    created_s = int(time.time())
    arn = _create_scheduled_query(
        logs,
        name=query_name,
        queryLanguage="CWLI",
        queryString=query_string,
        scheduleExpression="cron(* * * * ? *)",
        executionRoleArn=role_arn,
        logGroupIdentifiers=[group],
        startTimeOffset=3600,
        endTimeOffset=0,
        state="ENABLED",
        destinationConfiguration={
            "s3Configuration": {"destinationIdentifier": dest_uri, "roleArn": role_arn}
        },
    )
    ctx.on_cleanup(lambda: _delete_scheduled_query(logs, arn))

    rec = _first_settled_record(logs, arn, since_s=created_s - 120, timeout_s=300.0)
    assert rec["executionStatus"] == "Complete", f"execution record was {rec!r}"
    dests = rec.get("destinations") or []
    assert len(dests) == 1, f"expected exactly one destination entry, got {dests!r}"
    dest = dests[0]
    assert dest.get("destinationType") == "S3", f"destinationType was {dest!r}"
    assert dest.get("destinationIdentifier") == dest_uri, (
        f"destinationIdentifier {dest.get('destinationIdentifier')!r} != configured {dest_uri!r}"
    )
    assert dest.get("status") == "COMPLETE", f"S3 destination did not complete: {dest!r}"

    processed = urlparse(dest.get("processedIdentifier") or "")
    assert processed.scheme == "s3" and processed.netloc == bucket, (
        f"processedIdentifier does not name our bucket: {dest.get('processedIdentifier')!r}"
    )
    key = processed.path.lstrip("/")
    assert key.startswith(f"{prefix}/"), f"object key {key!r} is outside prefix {prefix!r}"
    assert key.endswith(f"{rec['queryId']}.json"), (
        f"object key {key!r} does not end with the execution's queryId {rec['queryId']!r}"
    )

    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    rows = json.loads(body)
    assert isinstance(rows, list), f"S3 result object is not a JSON array: {body[:400]!r}"
    got_messages = [r.get("@message") for r in rows]
    assert got_messages == [e["message"] for e in seeded], (
        f"result rows {got_messages!r} != seeded events in timestamp order"
    )
    want_ts = [_insights_ts(e["timestamp"]) for e in seeded]
    got_ts = [r.get("@timestamp") for r in rows]
    assert got_ts == want_ts, f"row timestamps {got_ts!r} != seeded timestamps {want_ts!r}"
    for r in rows:
        assert set(r) == {"@message", "@timestamp"}, (
            f"row carries fields beyond the projected two: {r!r}"
        )
    assert decoy["message"] not in body.decode(), f"decoy event leaked into results: {body!r}"

    # Every object under the prefix belongs to this query's runs (the scheduler keeps firing).
    keys = [
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    ]
    assert key in keys, f"processed object {key!r} absent from listing {keys!r}"
    stray = [k for k in keys if f"/{query_name}/" not in k or not k.endswith(".json")]
    assert stray == [], f"objects under {prefix!r} not attributable to {query_name!r}: {stray!r}"


def _insights_ts(ms: int) -> str:
    dt = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{ms % 1000:03d}"


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_insights_sees(logs, group: str, query_string: str, want: list[str]) -> None:
    def _probe():
        now = int(time.time())
        qid = logs.start_query(
            logGroupNames=[group], startTime=now - 3600, endTime=now + 60,
            queryString=query_string,
        )["queryId"]
        res = _poll_until(
            lambda: logs.get_query_results(queryId=qid),
            lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
            timeout_s=60.0, interval_s=2.0, description=f"Insights query {qid} finishes",
        )
        return [f["value"] for row in res["results"] for f in row if f["field"] == "@message"]

    _poll_until(_probe, lambda got: got == want, timeout_s=180.0, interval_s=5.0,
                description=f"Logs Insights returns the {len(want)} seeded events")


def _make_bucket(ctx, s3, prefix: str) -> str:
    bucket = ctx.unique_name(prefix)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    # A scheduled run already in flight when the query is deleted can still land an object,
    # so empty-then-delete is retried rather than attempted once.
    for _ in range(6):
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BucketNotEmpty":
                raise
            time.sleep(10)
    raise RuntimeError(f"bucket {bucket} never emptied")


def _make_role(ctx, iam, role_name: str, bucket: str, *, s3_actions: list[str]) -> str:
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sq-exec",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults",
                        "logs:DescribeLogGroups",
                    ],
                    "Resource": "*",
                },
                {"Effect": "Allow", "Action": s3_actions, "Resource": f"arn:aws:s3:::{bucket}/*"},
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sq-exec"))
    # IAM propagation exposes no pollable condition; the bounded retry on first use of the
    # role (in _create_scheduled_query) is what makes this correct, the sleep only cheaper.
    time.sleep(8)
    return arn


def _create_scheduled_query(logs, **kwargs) -> str:
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            return logs.create_scheduled_query(**kwargs)["scheduledQueryArn"]
        except ClientError as exc:
            last = exc
            if exc.response["Error"]["Code"] not in ("ValidationException", "AccessDeniedException"):
                raise
            time.sleep(5)
    raise AssertionError(f"CreateScheduledQuery never accepted the new role: {last}")


def _delete_scheduled_query(logs, arn: str) -> None:
    try:
        logs.delete_scheduled_query(identifier=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _first_settled_record(logs, arn: str, *, since_s: int, timeout_s: float) -> dict:
    """The earliest execution whose S3 destination has left IN_PROGRESS."""

    def _probe():
        hist = logs.get_scheduled_query_history(
            identifier=arn, startTime=since_s, endTime=int(time.time()) + 60
        ).get("triggerHistory", [])
        settled = [
            r for r in hist
            if r.get("executionStatus") not in (None, "Running")
            and (r.get("destinations") or [{}])[0].get("status") not in (None, "IN_PROGRESS")
        ]
        return sorted(settled, key=lambda r: r.get("triggeredTimestamp", 0))

    return _poll_until(_probe, bool, timeout_s=timeout_s, interval_s=10.0,
                       description=f"a settled execution of {arn} with an S3 destination")[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
