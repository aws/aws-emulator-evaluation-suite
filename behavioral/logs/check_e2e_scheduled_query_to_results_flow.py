"""e2e-scheduled-query-to-results-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-scheduled-query-to-results-flow"
GROUP = "e2e"
SERVICES = ["logs"]


# timing:real-time — schedule: 422 s
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A scheduled query created ENABLED runs on its cron schedule, its history records a Complete run whose
    results count exactly the ingested INFO events, and after deletion it reads ResourceNotFoundException with
    the exact message.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    log_group = ctx.unique_name("sim2real-behav-schedq-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _ignore(lambda: logs.delete_log_group(logGroupName=log_group)))
    log_group_arn = _log_group_arn(logs, log_group)

    stream_name = ctx.unique_name("sim2real-behav-schedq-stream-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    info_count = 5
    events = [
        {
            "timestamp": now_ms + i,
            "message": json.dumps({"level": "INFO", "requestId": f"r{i}"}),
        }
        for i in range(info_count)
    ]
    events.append(
        {"timestamp": now_ms + info_count, "message": json.dumps({"level": "WARN", "requestId": "w0"})}
    )
    logs.put_log_events(logGroupName=log_group, logStreamName=stream_name, logEvents=events)

    role_name = ctx.unique_name("sim2real-behav-schedq-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = ctx.unique_name("sim2real-behav-schedq-policy-")
    exec_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(exec_policy)
    )
    ctx.on_cleanup(
        lambda: _ignore(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    )

    query_string = "fields level | filter level = 'INFO' | stats count() as eventCount"
    scheduled_query_name = ctx.unique_name("sim2real-behav-schedq-")

    # IAM role trust takes a few seconds to become visible to other services.
    create_resp = _poll_until(
        lambda: _try_create_scheduled_query(
            logs, scheduled_query_name, query_string, log_group_arn, role_arn
        ),
        lambda resp: resp is not None,
        timeout_s=60,
        interval_s=5,
    )
    scheduled_query_arn = create_resp["scheduledQueryArn"]
    ctx.on_cleanup(
        lambda: _ignore(lambda: logs.delete_scheduled_query(identifier=scheduled_query_arn))
    )
    assert create_resp["state"] == "ENABLED"

    created_at_ms = int(time.time() * 1000)

    def _latest_complete_trigger() -> dict | None:
        history = logs.get_scheduled_query_history(
            identifier=scheduled_query_arn,
            startTime=created_at_ms - 60_000,
            endTime=int(time.time() * 1000) + 60_000,
        )
        for record in history.get("triggerHistory", []):
            if record["executionStatus"] == "Complete":
                return record
        return None

    trigger = _poll_until(
        _latest_complete_trigger,
        lambda t: t is not None,
        timeout_s=1200,
        interval_s=30,
    )

    query_id = trigger["queryId"]
    results = logs.get_query_results(queryId=query_id)
    assert results["status"] == "Complete"

    values = {field["field"]: field["value"] for row in results["results"] for field in row}
    assert values.get("eventCount") == str(info_count)

    logs.delete_scheduled_query(identifier=scheduled_query_arn)
    code, message = _error(lambda: logs.get_scheduled_query(identifier=scheduled_query_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetScheduledQuery after delete, got {code!r}"
    )
    assert message == f"Scheduled query with identifier {scheduled_query_arn} not found", (
        f"unexpected GetScheduledQuery message after delete: {message!r}"
    )


def _try_create_scheduled_query(
    logs_client: Any, name: str, query_string: str, log_group_arn: str, role_arn: str
) -> dict | None:
    from botocore.exceptions import ClientError

    try:
        return logs_client.create_scheduled_query(
            name=name,
            queryLanguage="CWLI",
            queryString=query_string,
            logGroupIdentifiers=[log_group_arn],
            scheduleExpression="cron(*/15 * * * ? *)",
            # startTimeOffset is a required field on real AWS despite not being modelled as
            # such; 3600/0 is the convention used by every other scheduled-query check in
            # this suite, matching the query's lookback window to the cron's own cadence.
            startTimeOffset=3600,
            endTimeOffset=0,
            executionRoleArn=role_arn,
            state="ENABLED",
            tags={"Sim2RealOwner": "behavioral-suite"},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AccessDeniedException":
            return None
        raise


def _ignore(fn: Any) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _log_group_arn(logs_client: Any, name: str) -> str:
    resp = logs_client.describe_log_groups(logGroupNamePrefix=name)
    for group in resp["logGroups"]:
        if group["logGroupName"] == name:
            arn = group["arn"]
            # DescribeLogGroups returns the ARN with a trailing ":*".
            # CreateScheduledQuery's logGroupIdentifiers validates against a pattern that
            # rejects that suffix, so it must be stripped before use.
            return arn[:-2] if arn.endswith(":*") else arn
    raise AssertionError(f"log group {name} not found via DescribeLogGroups")


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe: Any, predicate: Any, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
