"""log-events-forwarded-by-the-dataset-integration-query-back-exactly."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-events-forwarded-by-the-dataset-integration-query-back-exactly"
GROUP = "dataset-ingest"
SERVICES = ["cloudwatchomni", "logs", "observabilityadmin"]

_POLL_S = 3.0
_ARRIVAL_CAP_S = 300.0


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _execution_role(ctx, log_group: str) -> str:
    """A role CloudWatch Logs assumes for this account's dataset integration, allowed to forward
    only ``log_group``; deleted at cleanup. Returns its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cwo-ds-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "logs.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"aws:SourceAccount": ctx.account},
            "ArnLike": {"aws:SourceArn": (
                f"arn:aws:observabilityadmin:{ctx.region}:{ctx.account}:dataset-integration/default"
            )},
        },
    }]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "logs:IntegrateWithDataset",
         "Resource": [f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{log_group}"]},
        {"Effect": "Allow", "Action": "cloudwatch:PutRecords", "Resource": "*"},
    ]}
    iam.put_role_policy(RoleName=name, PolicyName="forward", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="forward"),
                             "NoSuchEntity"))
    return arn


def _window() -> str:
    """A WHERE predicate bounding `@timestamp` around now, as the default dataset requires."""
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now + datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"`@timestamp` BETWEEN to_timestamp('{start}') AND to_timestamp('{end}')"


def _query(ctx, cwo, session_id: str, sql: str) -> list:
    """The rows of a completed query."""
    query_id = cwo.start_telemetry_query(sessionId=session_id, queryString=sql)["queryId"]
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        res = cwo.get_telemetry_query_results(queryId=query_id)
        if res["status"] != "RUNNING":
            assert res["status"] == "Complete", f"query ended {res['status']!r}: {sql}"
            return res.get("rows") or []
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("query to finish: the run budget ended first; not graded")
            raise AssertionError(f"query still RUNNING at its deadline: {sql}")
        time.sleep(1.0)


def _stamp(ms: int) -> str:
    """The `@timestamp` text a query returns for an event time in epoch milliseconds."""
    moment = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "plane:data",
      "dp:api", "resource:account-singleton:observabilityadmin-dataset-integration")
def run(ctx) -> None:
    """Log events written to a log group the dataset integration forwards come back from a query
    over the default dataset exactly as written, and a second integration is refused.
    """
    oa = ctx.client("observabilityadmin")
    logs = ctx.client("logs")
    cwo = ctx.client("cloudwatchomni")

    prior = oa.list_dataset_integrations()["DatasetIntegrationSummaries"]
    assert prior == [], f"the account must hold no dataset integration first, found {len(prior)}"

    log_group = ctx.unique_name("sim2real-behav-cwo-logs-")
    role_arn = _execution_role(ctx, log_group)
    integration_arn = f"arn:aws:observabilityadmin:{ctx.region}:{ctx.account}:dataset-integration/default"

    created = oa.create_dataset_integration(RoleArn=role_arn)
    ctx.on_cleanup(_teardown(lambda: oa.delete_dataset_integration(Arn=integration_arn),
                             "ResourceNotFoundException"))
    assert (created["Arn"], created["RoleArn"]) == (integration_arn, role_arn), (
        f"unexpected integration identity {created['Arn']!r} / {created['RoleArn']!r}"
    )
    code, message = _error(lambda: oa.create_dataset_integration(RoleArn=role_arn))
    assert (code, message) == ("ConflictException", "Dataset integration already exists for this account."), (
        f"unexpected answer to a second integration: {code}: {message!r}"
    )
    got = oa.get_dataset_integration(Arn=integration_arn)
    assert (got["Arn"], got["RoleArn"]) == (integration_arn, role_arn), (
        f"GetDatasetIntegration reads back {got['Arn']!r} / {got['RoleArn']!r}"
    )

    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=log_group),
                             "ResourceNotFoundException"))
    for stream in ("warm-up", "orders"):
        logs.create_log_stream(logGroupName=log_group, logStreamName=stream)

    session_id = cwo.start_telemetry_query_session(
        sessionName=ctx.unique_name("sim2real-behav-cwo-sess-")
    )["sessionId"]
    ctx.on_cleanup(_teardown(lambda: cwo.stop_telemetry_query_session(sessionId=session_id),
                             "ResourceNotFoundException"))

    # Forwarding starts a short while after the integration is created and drops what was written
    # before; a warm-up line repeated until one is queryable marks the moment it is live.
    budget = _budget_s(ctx, _ARRIVAL_CAP_S)
    deadline = time.monotonic() + budget
    sent = 0
    while True:
        sent += 1
        logs.put_log_events(logGroupName=log_group, logStreamName="warm-up", logEvents=[
            {"timestamp": int(time.time() * 1000), "message": f"warm-up {sent}"},
        ])
        rows = _query(ctx, cwo, session_id, (
            f"SELECT `@message` FROM default WHERE {_window()} AND `@logGroupName` = '{log_group}' "
            "AND `@logStream` = 'warm-up'"
        ))
        if rows:
            break
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("forwarding to start: the run budget ended first; not graded")
            raise AssertionError(f"none of {sent} warm-up line(s) reached the dataset in {budget:.0f}s")
        time.sleep(_POLL_S)

    # Millisecond parts with no trailing zero, so each `@timestamp` text is unambiguous.
    base = int(time.time()) * 1000 + 123
    events = [
        {"timestamp": base + 111 * i, "message": f"order={i} sku=SKU-{i:03d} amount={7 * i}"}
        for i in range(3)
    ]
    logs.put_log_events(logGroupName=log_group, logStreamName="orders", logEvents=events)
    expected = [
        {"@timestamp": _stamp(e["timestamp"]), "@logGroupName": log_group, "@logStream": "orders",
         "@message": e["message"]}
        for e in events
    ]
    sql = (
        f"SELECT `@timestamp`, `@logGroupName`, `@logStream`, `@message` FROM default WHERE {_window()} "
        f"AND `@logGroupName` = '{log_group}' AND `@logStream` = 'orders' ORDER BY `@timestamp`"
    )
    budget = _budget_s(ctx, _ARRIVAL_CAP_S)
    deadline = time.monotonic() + budget
    while True:
        rows = _query(ctx, cwo, session_id, sql)
        if len(rows) >= len(expected):
            break
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the order lines to arrive: the run budget ended first; not graded")
            raise AssertionError(f"{len(rows)} of {len(expected)} order line(s) queryable after {budget:.0f}s")
        time.sleep(_POLL_S)
    assert rows == expected, f"expected exactly the written events {expected!r}, got {rows!r}"

    counted = _query(ctx, cwo, session_id, (
        f"SELECT `@logStream` AS stream, count(*) AS n FROM default WHERE {_window()} "
        f"AND `@logGroupName` = '{log_group}' AND `@logStream` = 'orders' GROUP BY `@logStream`"
    ))
    assert counted == [{"stream": "orders", "n": "3"}], f"unexpected aggregate {counted!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
