"""scheduled-query-lifecycle-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-query-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Scheduled queries are visible via Get/List, mutable via Update, and removed by Delete;
    the deleted identifier then refuses both a read and a further mutation.
    """
    logs = ctx.client("logs")
    log_group_name, _ = _create_log_group(ctx)
    role_arn = _create_role(ctx, ["logs.amazonaws.com", "scheduler.amazonaws.com"])
    query_name = ctx.unique_name("sim2real-sq-")

    # A freshly created execution role can take a few seconds to propagate through
    # IAM; retry only on that specific, expected transient error.
    create_resp = _create_scheduled_query_with_retry(
        logs,
        name=query_name,
        queryLanguage="CWLI",
        queryString="fields @timestamp, @message | limit 20",
        scheduleExpression="cron(0 * * * ? *)",
        # Real AWS models startTimeOffset as an integer number of seconds
        # (the lookback window before the scheduled fire time), not an
        # ISO-8601 duration string.
        startTimeOffset=3600,
        executionRoleArn=role_arn,
        logGroupIdentifiers=[log_group_name],
        state="ENABLED",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    # state is explicit input: a target that silently defaulted to DISABLED fails this.
    assert create_resp["state"] == "ENABLED", (
        f"expected state ENABLED (explicitly requested at creation), got {create_resp['state']!r}"
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_scheduled_query(identifier=query_name)))

    got = logs.get_scheduled_query(identifier=query_name)
    assert got["name"] == query_name, f"expected name {query_name!r}, got {got['name']!r}"
    assert got["queryString"] == "fields @timestamp, @message | limit 20", (
        f"expected the created queryString, got {got['queryString']!r}"
    )
    assert got["scheduleExpression"] == "cron(0 * * * ? *)", (
        f"expected the created scheduleExpression, got {got['scheduleExpression']!r}"
    )

    def _query_listed() -> bool:
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            resp = logs.list_scheduled_queries(**kwargs)
            if any(q.get("name") == query_name for q in resp.get("scheduledQueries", [])):
                return True
            next_token = resp.get("nextToken")
            if not next_token:
                return False

    listed = _poll_until(_query_listed, lambda found: found is True, timeout_s=30.0)
    assert listed is True, f"{query_name} never appeared in ListScheduledQueries"

    # AWS re-validates queryString against the log groups on every update, so
    # logGroupIdentifiers must be supplied again or the update fails with ValidationException.
    logs.update_scheduled_query(
        identifier=query_name,
        queryLanguage="CWLI",
        queryString="fields @timestamp, @message | limit 50",
        scheduleExpression="cron(0 0/2 * * ? *)",
        startTimeOffset=3600,
        executionRoleArn=role_arn,
        logGroupIdentifiers=[log_group_name],
    )
    updated = logs.get_scheduled_query(identifier=query_name)
    assert updated["queryString"] == "fields @timestamp, @message | limit 50", (
        f"expected the updated queryString, got {updated['queryString']!r}"
    )
    assert updated["scheduleExpression"] == "cron(0 0/2 * * ? *)", (
        f"expected the updated scheduleExpression, got {updated['scheduleExpression']!r}"
    )

    logs.delete_scheduled_query(identifier=query_name)
    _wait_for_not_found(lambda: logs.get_scheduled_query(identifier=query_name))

    # The dead identifier must refuse a mutation too, not just a read.
    mutate_code, mutate_message = _error_code(
        lambda: logs.update_scheduled_query(
            identifier=query_name,
            queryLanguage="CWLI",
            queryString="fields @timestamp | limit 1",
            scheduleExpression="cron(0 0/2 * * ? *)",
            startTimeOffset=3600,
            executionRoleArn=role_arn,
            logGroupIdentifiers=[log_group_name],
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateScheduledQuery on a deleted query to fail with ResourceNotFoundException, "
        f"got {mutate_code!r}: {mutate_message!r}"
    )
    assert mutate_message == f"Scheduled query with identifier {query_name} not found", (
        f"unexpected deleted-scheduled-query message: {mutate_message!r}"
    )



def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_not_found(fn: Callable[[], Any], timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            fn()
            code = None  # still readable: the delete has not propagated yet
        except ClientError as e:
            code = e.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        last_code = code
        time.sleep(interval_s)
    raise AssertionError(f"expected ResourceNotFoundException, got {last_code!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_scheduled_query_with_retry(logs_client, retry_seconds: float = 60.0, **kwargs) -> dict[str, Any]:
    # A just-created IAM execution role can take a few seconds to propagate;
    # retry only on that specific, expected transient error.
    deadline = time.monotonic() + retry_seconds
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return logs_client.create_scheduled_query(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ResourceNotFoundException"):
                last_exc = e
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"execution role never propagated for CreateScheduledQuery: {last_exc}")


def _create_log_group(ctx) -> tuple[str, str]:
    logs_client = ctx.client("logs")
    name = ctx.unique_name("sim2real-logs-lg-")
    logs_client.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs_client.delete_log_group(logGroupName=name))
    arn = logs_client.describe_log_groups(logGroupNamePrefix=name)["logGroups"][0]["arn"]
    return name, arn


def _create_role(ctx, trust_services: list[str]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-logs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_services}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
