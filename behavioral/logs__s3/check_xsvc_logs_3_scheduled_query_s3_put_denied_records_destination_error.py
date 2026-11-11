"""xsvc-logs-3-scheduled-query-s3-put-denied-records-destination-error."""
from __future__ import annotations

import json
import time
import uuid
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-logs-3-scheduled-query-s3-put-denied-records-destination-error"
GROUP = "scheduled-query-destination"
SERVICES = ["logs", "s3"]


# timing:real-time — schedule: 60 s
@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A scheduled query whose destination role lacks s3:PutObject completes, but its S3 destination
    records status ERROR naming s3:PutObject and nothing is written, while a control query writes;
    repointing the role makes the next run write under the same prefix.
    """
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    tag = uuid.uuid4().hex[:12]
    marker = f"sim2real-sqdeny-{tag}"
    bucket = _make_bucket(ctx, s3, "sim2real-xsvc-sqdeny-")
    good_prefix, bad_prefix = "good", "bad"

    group = ctx.unique_name("sim2real-xsvc-sqdeny-lg-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName="seed")
    base = int(time.time() * 1000) - 10_000
    seeded = [{"timestamp": base + i, "message": f"{marker} row={i}"} for i in range(2)]
    resp = logs.put_log_events(logGroupName=group, logStreamName="seed", logEvents=seeded)
    assert not resp.get("rejectedLogEventsInfo"), f"seed rejected: {resp!r}"
    query_string = f"fields @message | filter @message like /{marker}/ | sort @timestamp asc"
    _wait_insights_sees(logs, group, query_string, [e["message"] for e in seeded])

    good_role = _make_role(ctx, iam, ctx.unique_name("sim2real-xsvc-sqdeny-ok-"), bucket,
                           s3_actions=["s3:PutObject"])
    # The ONE broken thing: the destination role can read the bucket but not write to it.
    bad_role = _make_role(ctx, iam, ctx.unique_name("sim2real-xsvc-sqdeny-no-"), bucket,
                          s3_actions=["s3:GetObject"])

    common = dict(
        queryLanguage="CWLI",
        queryString=query_string,
        scheduleExpression="cron(* * * * ? *)",
        logGroupIdentifiers=[group],
        startTimeOffset=3600,
        endTimeOffset=0,
        state="ENABLED",
    )
    created_s = int(time.time())
    bad_uri = f"s3://{bucket}/{bad_prefix}/"
    bad_arn = _create_scheduled_query(
        logs, name=ctx.unique_name("sim2real-xsvc-sqdeny-qno-"), executionRoleArn=bad_role,
        destinationConfiguration={
            "s3Configuration": {"destinationIdentifier": bad_uri, "roleArn": bad_role}
        },
        **common,
    )
    ctx.on_cleanup(lambda: _delete_scheduled_query(logs, bad_arn))
    good_uri = f"s3://{bucket}/{good_prefix}/"
    good_arn = _create_scheduled_query(
        logs, name=ctx.unique_name("sim2real-xsvc-sqdeny-qok-"), executionRoleArn=good_role,
        destinationConfiguration={
            "s3Configuration": {"destinationIdentifier": good_uri, "roleArn": good_role}
        },
        **common,
    )
    ctx.on_cleanup(lambda: _delete_scheduled_query(logs, good_arn))

    # --- Positive control: the same query shape on the same bucket writes its object.
    good = _first_settled_record(logs, good_arn, since_s=created_s - 120, timeout_s=240.0)
    gdest = (good.get("destinations") or [{}])[0]
    assert good["executionStatus"] == "Complete" and gdest.get("status") == "COMPLETE", (
        f"positive control did not deliver: {good!r}"
    )
    gkey = urlparse(gdest.get("processedIdentifier") or "").path.lstrip("/")
    assert gkey.startswith(f"{good_prefix}/"), f"control object key was {gkey!r}"
    grows = json.loads(s3.get_object(Bucket=bucket, Key=gkey)["Body"].read())
    assert [r.get("@message") for r in grows] == [e["message"] for e in seeded], (
        f"control rows were {grows!r}"
    )

    # --- The denied destination: the query ran, the write was refused and recorded.
    bad = _first_settled_record(logs, bad_arn, since_s=created_s - 120, timeout_s=180.0)
    assert bad["executionStatus"] == "Complete", (
        f"the query itself should still complete when only its destination is denied: {bad!r}"
    )
    bdests = bad.get("destinations") or []
    assert len(bdests) == 1, f"expected one destination entry, got {bdests!r}"
    bdest = bdests[0]
    assert bdest.get("destinationType") == "S3", f"destinationType was {bdest!r}"
    assert bdest.get("destinationIdentifier") == bad_uri, f"destinationIdentifier was {bdest!r}"
    # AWS reports "ERROR", a value the model's ActionStatus enum does not declare.
    assert bdest.get("status") == "ERROR", f"denied destination status was {bdest!r}"
    msg = bdest.get("errorMessage") or ""
    assert msg.startswith("[AccessDenied]"), f"errorMessage does not lead with AccessDenied: {msg!r}"
    assert "s3:PutObject" in msg, f"errorMessage does not name s3:PutObject: {msg!r}"
    assert bad_role.split("/")[-1] in msg, f"errorMessage does not name the denied role: {msg!r}"
    assert "processedIdentifier" not in bdest, (
        f"a denied write must not report a processed object: {bdest!r}"
    )
    # Barrier for the absence: the control has delivered at least once by now, so the broken
    # side's object -- had the write been allowed -- would have made the same trip.
    assert _keys(s3, bucket, f"{bad_prefix}/") == [], (
        f"objects exist under the denied prefix: {_keys(s3, bucket, f'{bad_prefix}/')!r}"
    )

    # --- Repair the one broken thing and require the SAME prefix to receive.
    repaired_s = int(time.time())
    logs.update_scheduled_query(
        identifier=bad_arn, executionRoleArn=bad_role,
        destinationConfiguration={
            "s3Configuration": {"destinationIdentifier": bad_uri, "roleArn": good_role}
        },
        **common,
    )
    fixed = _poll_until(
        lambda: [
            r for r in logs.get_scheduled_query_history(
                identifier=bad_arn, startTime=repaired_s - 5, endTime=int(time.time()) + 60
            ).get("triggerHistory", [])
            if r.get("triggeredTimestamp", 0) > repaired_s
            and (r.get("destinations") or [{}])[0].get("status") == "COMPLETE"
        ],
        bool, timeout_s=180.0, interval_s=10.0,
        description="the repaired query's next run reports its S3 destination COMPLETE",
    )[0]
    fkey = urlparse(fixed["destinations"][0].get("processedIdentifier") or "").path.lstrip("/")
    assert fkey in _keys(s3, bucket, f"{bad_prefix}/"), (
        f"repaired run reported {fkey!r} but it is not under {bad_prefix}/"
    )


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


def _keys(s3, bucket: str, prefix: str) -> list[str]:
    return [
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for o in page.get("Contents", [])
    ]


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
