"""concurrent-create-scheduled-query-same-name-exactly-one-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-scheduled-query-same-name-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateScheduledQuery calls racing on the same name resolve to
    exactly one live scheduled query and exactly one duplicate-name ConflictException
    -- never two live resources and never two successes."""
    logs = ctx.client("logs")
    role_arn = _create_execution_role(ctx)
    log_group_name = ctx.unique_name("/sim2real-behav/sq-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    name = ctx.unique_name("sim2real-behav-sq-")
    query_string = "fields @timestamp, @message | limit 1"
    schedule_expression = "cron(0 12 * * ? *)"

    def _create() -> dict[str, Any]:
        return logs.create_scheduled_query(
            name=name,
            queryLanguage="CWLI",
            queryString=query_string,
            logGroupIdentifiers=[log_group_name],
            scheduleExpression=schedule_expression,
            executionRoleArn=role_arn,
            startTimeOffset=300,
            state="DISABLED",
        )

    def _racer() -> dict[str, Any]:
        # A freshly created IAM role can take a few seconds to propagate; retry only on
        # that specific, expected transient error and never swallow the ConflictException
        # this check exists to observe.
        last_exc: ClientError | None = None
        for _ in range(10):
            try:
                return {"ok": True, "value": _create()}
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "AccessDeniedException":
                    last_exc = exc
                    time.sleep(2)
                    continue
                return {"ok": False, "code": code, "message": exc.response["Error"].get("Message")}
        raise AssertionError(f"execution role never propagated for CreateScheduledQuery: {last_exc}")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_racer) for _ in range(2)]
        results = [f.result() for f in futures]

    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]

    assert len(successes) == 1, f"expected exactly one success, got: {results}"
    assert len(failures) == 1, f"expected exactly one failure, got: {results}"
    assert failures[0]["code"] == "ConflictException", (
        f"expected the losing racer to fail with ConflictException, got {failures[0]['code']!r}"
    )
    expected = f"Scheduled query with identifier {name} already exists"
    assert failures[0]["message"] == expected, (
        f"expected the losing racer's message {expected!r}, got {failures[0]['message']!r}"
    )

    arn = successes[0]["value"]["scheduledQueryArn"]
    ctx.on_cleanup(lambda: logs.delete_scheduled_query(identifier=arn))

    # No duplicate live resource: exactly one scheduled query with this name exists.
    matches = _list_scheduled_queries_by_name(ctx, name)
    assert len(matches) == 1, f"expected exactly one live scheduled query, found: {matches}"
    assert matches[0]["scheduledQueryArn"] == arn, (
        f"expected the sole live scheduled query to be the winning racer's own resource "
        f"{arn!r}, found {matches[0]['scheduledQueryArn']!r}"
    )


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sqrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-behav-sq-exec-policy"
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
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _list_scheduled_queries_by_name(ctx, name: str) -> list[dict[str, Any]]:
    logs = ctx.client("logs")
    matches: list[dict[str, Any]] = []
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = logs.list_scheduled_queries(**kwargs)
        matches.extend(q for q in resp.get("scheduledQueries", []) if q.get("name") == name)
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return matches


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
