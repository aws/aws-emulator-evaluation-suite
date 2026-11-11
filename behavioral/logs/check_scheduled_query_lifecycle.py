"""scheduled-query-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "scheduled-query-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScheduledQuery -> GetScheduledQuery/ListScheduledQueries -> DeleteScheduledQuery
    moves a scheduled query through its full lifecycle and it disappears from listings
    after deletion."""
    logs = ctx.client("logs")

    log_group_name, log_group_arn = _create_log_group(ctx, "sim2real-behav-sqlg-")
    role_name, role_arn = _create_execution_role(ctx)
    _attach_execution_policy(ctx, role_name)

    query_name = ctx.unique_name("sim2real-behav-sq-")
    create_resp = _create_scheduled_query_with_retry(
        logs,
        name=query_name,
        queryLanguage="CWLI",
        queryString="fields @timestamp, @message | limit 1",
        scheduleExpression="cron(0 12 * * ? *)",
        executionRoleArn=role_arn,
        logGroupIdentifiers=[log_group_arn],
        state="ENABLED",
        startTimeOffset=3600,
        tags={"sim2real": "scheduled-query-lifecycle"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_scheduled_query(identifier=query_name)))
    assert create_resp["state"] == "ENABLED", f"expected ENABLED, got {create_resp['state']!r}"
    assert create_resp["scheduledQueryArn"], "CreateScheduledQuery returned no scheduledQueryArn"

    got = logs.get_scheduled_query(identifier=query_name)
    assert got["name"] == query_name, f"expected name {query_name!r}, got {got['name']!r}"
    assert got["queryString"] == "fields @timestamp, @message | limit 1", (
        f"expected the created queryString, got {got['queryString']!r}"
    )
    assert got["executionRoleArn"] == role_arn, (
        f"expected executionRoleArn {role_arn!r}, got {got['executionRoleArn']!r}"
    )
    assert got["state"] == "ENABLED", f"expected ENABLED, got {got['state']!r}"

    listed = _collect_all(logs.list_scheduled_queries, "scheduledQueries")
    names = {q["name"] for q in listed}
    assert query_name in names, f"{query_name} not present in ListScheduledQueries: {names}"

    logs.delete_scheduled_query(identifier=query_name)

    code, message = _error_code(lambda: logs.get_scheduled_query(identifier=query_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"Scheduled query with identifier {query_name} not found", (
        f"unexpected deleted-scheduled-query message: {message!r}"
    )

    def _probe():
        return _collect_all(logs.list_scheduled_queries, "scheduledQueries")

    final = _poll_until(_probe, lambda items: query_name not in {q["name"] for q in items}, timeout_s=30.0)
    assert query_name not in {q["name"] for q in final}, "scheduled query still listed after delete"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _collect_all(call, resp_key: str, **kwargs) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = call(**params)
        items.extend(resp.get(resp_key, []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


def _create_log_group(ctx, prefix: str):
    logs = ctx.client("logs")
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name, tags={"sim2real": "scheduled-query-lifecycle"})
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_log_group(logGroupName=name)))
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    arn = resp["logGroups"][0]["arn"]
    # DescribeLogGroups returns the ARN with a trailing ":*" (a legacy artifact). APIs that
    # take a log group identifier as an ARN -- such as CreateScheduledQuery's
    # logGroupIdentifiers -- validate against a pattern that rejects that suffix, so it must
    # be stripped before use.
    if arn.endswith(":*"):
        arn = arn[:-2]
    return name, arn


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sqrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "scheduled-query-lifecycle"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name)))
    return role_name, role_arn


def _attach_execution_policy(ctx, role_name: str):
    iam = ctx.client("iam")
    policy_name = "sim2real-behav-sq-exec-policy"
    doc = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    ctx.on_cleanup(
        lambda: _safe_call(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )


def _create_scheduled_query_with_retry(logs_client, retry_seconds: float = 60.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + retry_seconds
    last_exc = None
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
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
