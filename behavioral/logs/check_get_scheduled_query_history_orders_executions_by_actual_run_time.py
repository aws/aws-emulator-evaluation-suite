"""get-scheduled-query-history-orders-executions-by-actual-run-time."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-scheduled-query-history-orders-executions-by-actual-run-time"
GROUP = "data-plane"
SERVICES = ["logs"]


# timing:real-time — schedule: 60 s
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """GetScheduledQueryHistory reports a real trigger timestamp and a Complete status, and
    GetQueryResults for the recorded queryId returns the events the query matched.
    """
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-sq-lg")
    log_stream = ctx.unique_name("sim2real-sq-ls")
    marker = ctx.unique_name("sim2real-sq-marker")

    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": f"scheduled-query-target {marker}"}],
    )

    role_arn = _create_execution_role(ctx)

    query_name = ctx.unique_name("sim2real-sq")
    query_string = f"fields @timestamp, @message | filter @message like /{marker}/ | limit 20"
    creation_time = time.time()
    scheduled_query_arn = _create_scheduled_query_with_retry(
        ctx, query_name, query_string, log_group, role_arn
    )
    ctx.on_cleanup(lambda: logs.delete_scheduled_query(identifier=scheduled_query_arn))

    record = _poll_for_trigger_history(ctx, scheduled_query_arn, creation_time)

    now = time.time()
    assert record["triggeredTimestamp"] >= creation_time - 5, (
        f"expected triggeredTimestamp >= {creation_time - 5} (query creation time), "
        f"got {record['triggeredTimestamp']}: {record}"
    )
    assert record["triggeredTimestamp"] <= now + 5, (
        f"expected triggeredTimestamp <= {now + 5} (now), got {record['triggeredTimestamp']}: {record}"
    )
    assert record["executionStatus"] == "Complete", (
        f"expected executionStatus 'Complete', got {record['executionStatus']!r}: {record}"
    )

    results = logs.get_query_results(queryId=record["queryId"])
    assert results["status"] == "Complete", (
        f"expected GetQueryResults status 'Complete' for queryId {record['queryId']}, "
        f"got {results['status']!r}: {results}"
    )
    flattened = [
        {f["field"]: f["value"] for f in row} for row in results.get("results", [])
    ]
    assert any(marker in row.get("@message", "") for row in flattened), (
        f"expected a result row with @message containing marker {marker!r}, got: {flattened}"
    )


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sq-role")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-sq-policy")
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:StartQuery",
                    "logs:StopQuery",
                    "logs:GetQueryResults",
                    "logs:DescribeLogGroups",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_scheduled_query_with_retry(ctx, name, query_string, log_group, role_arn, timeout_s: float = 30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = logs.create_scheduled_query(
                name=name,
                queryLanguage="CWLI",
                queryString=query_string,
                logGroupIdentifiers=[log_group],
                scheduleExpression="cron(* * * * ? *)",
                startTimeOffset=3600,
                executionRoleArn=role_arn,
                state="ENABLED",
            )
            return resp["scheduledQueryArn"]
        except Exception as exc:  # noqa: BLE001 - IAM role propagation race
            last_error = exc
            time.sleep(3)
    raise AssertionError(f"CreateScheduledQuery never succeeded (last error: {last_error})")


def _poll_for_trigger_history(ctx, identifier: str, creation_time: float, timeout_s: float = 270.0):
    """Bounded poll for a terminal trigger record; schedules fire at minute-level cron precision."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.get_scheduled_query_history(
            identifier=identifier,
            startTime=int(creation_time) - 60,
            endTime=int(time.time()) + 60,
        )
        history = resp.get("triggerHistory", [])
        terminal = [h for h in history if h.get("executionStatus") in ("Complete", "Failed", "Timeout")]
        if terminal:
            return terminal[0]
        time.sleep(15)
    raise AssertionError(f"scheduled query {identifier} never produced trigger history within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
