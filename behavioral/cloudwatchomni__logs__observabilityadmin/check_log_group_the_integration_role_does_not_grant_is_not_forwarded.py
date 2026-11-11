"""log-group-the-integration-role-does-not-grant-is-not-forwarded."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-group-the-integration-role-does-not-grant-is-not-forwarded"
GROUP = "dataset-ingest"
SERVICES = ["cloudwatchomni", "logs", "observabilityadmin"]

_POLL_S = 3.0
_ARRIVAL_CAP_S = 300.0


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


def _latency(ctx, observe, cap_s: float, poll_s: float):
    """``(seconds, result)`` until ``observe()`` first returns something truthy: the positive's L.
    The wait is ``cap_s``, bounded by the run budget."""
    budget_s = _budget_s(ctx, cap_s)
    start = time.monotonic()
    while True:
        result = observe()
        if result:
            return time.monotonic() - start, result
        if time.monotonic() - start > budget_s:
            if _budget_spent(ctx):
                raise TimeoutError("the positive control to arrive: the run budget ended first; not graded")
            raise AssertionError(f"the positive control saw nothing in {budget_s:.0f}s")
        time.sleep(poll_s)


def _absent_for(ctx, observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 3.0) -> list:
    """Everything ``observe()`` returned over ``max(floor_s, factor * latency_s)`` seconds. A window
    the run budget cannot hold is not shortened: the check is not graded."""
    window = max(floor_s, factor * latency_s)
    left = ctx.time_left()
    if left is not None and window > left - 5.0:
        raise TimeoutError(
            f"a {window:.0f}s absence window: the run budget has {left:.0f}s left; not graded"
        )
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "plane:data", "dp:api",
      "resource:account-singleton:observabilityadmin-dataset-integration")
def run(ctx) -> None:
    """A log group the integration's execution role does not grant logs:IntegrateWithDataset on
    never reaches the default dataset, while a line written after it to the granted group does.
    """
    oa = ctx.client("observabilityadmin")
    logs = ctx.client("logs")
    cwo = ctx.client("cloudwatchomni")

    prior = oa.list_dataset_integrations()["DatasetIntegrationSummaries"]
    assert prior == [], f"the account must hold no dataset integration first, found {len(prior)}"

    granted = ctx.unique_name("sim2real-behav-cwo-in-")
    withheld = ctx.unique_name("sim2real-behav-cwo-out-")
    role_arn = _execution_role(ctx, granted)
    integration_arn = f"arn:aws:observabilityadmin:{ctx.region}:{ctx.account}:dataset-integration/default"
    oa.create_dataset_integration(RoleArn=role_arn)
    ctx.on_cleanup(_teardown(lambda: oa.delete_dataset_integration(Arn=integration_arn),
                             "ResourceNotFoundException"))

    for group in (granted, withheld):
        logs.create_log_group(logGroupName=group)
        ctx.on_cleanup(_teardown(lambda group=group: logs.delete_log_group(logGroupName=group),
                                 "ResourceNotFoundException"))
        logs.create_log_stream(logGroupName=group, logStreamName="app")

    session_id = cwo.start_telemetry_query_session(
        sessionName=ctx.unique_name("sim2real-behav-cwo-sess-")
    )["sessionId"]
    ctx.on_cleanup(_teardown(lambda: cwo.stop_telemetry_query_session(sessionId=session_id),
                             "ResourceNotFoundException"))

    def rows_of(group: str, marker: str) -> list:
        return _query(ctx, cwo, session_id, (
            f"SELECT `@logGroupName`, `@message` FROM default WHERE {_window()} "
            f"AND `@logGroupName` = '{group}' AND `@message` LIKE '{marker} %'"
        ))

    # Forwarding starts a short while after the integration is created and drops what was written
    # before; a warm-up line repeated until one is queryable marks the moment it is live.
    budget = _budget_s(ctx, _ARRIVAL_CAP_S)
    deadline = time.monotonic() + budget
    sent = 0
    while True:
        sent += 1
        logs.put_log_events(logGroupName=granted, logStreamName="app", logEvents=[
            {"timestamp": int(time.time() * 1000), "message": f"warm-up {sent}"},
        ])
        if rows_of(granted, "warm-up"):
            break
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("forwarding to start: the run budget ended first; not graded")
            raise AssertionError(f"none of {sent} warm-up line(s) reached the dataset in {budget:.0f}s")
        time.sleep(_POLL_S)

    logs.put_log_events(logGroupName=withheld, logStreamName="app", logEvents=[
        {"timestamp": int(time.time() * 1000), "message": "event withheld-line"},
    ])
    logs.put_log_events(logGroupName=granted, logStreamName="app", logEvents=[
        {"timestamp": int(time.time() * 1000), "message": "event granted-line"},
    ])
    latency, control = _latency(ctx, lambda: rows_of(granted, "event"), _ARRIVAL_CAP_S, _POLL_S)
    assert control == [{"@logGroupName": granted, "@message": "event granted-line"}], (
        f"the granted group's line reads back as {control!r}"
    )
    seen = _absent_for(ctx, lambda: rows_of(withheld, "event"), latency)
    assert seen == [], f"{len(seen)} row(s) from the withheld log group reached the dataset: {seen!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
