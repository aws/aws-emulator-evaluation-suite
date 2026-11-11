"""scheduled-query-history-recorded."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "scheduled-query-history-recorded"
GROUP = "state-machine"
SERVICES = ["logs"]


# timing:real-time — schedule: 60 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Executions of a scheduled query produce entries retrievable via
    GetScheduledQueryHistory."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-sqh-lg-")
    stream_name = ctx.unique_name("sim2real-sqh-ls-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": "sim2real scheduled query history seed"}],
    )
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns the ARN with a trailing ":*". APIs that
    # take a log group identifier as an ARN -- such as CreateScheduledQuery's
    # logGroupIdentifiers -- validate against a pattern that rejects that suffix, so it must
    # be stripped before use.
    if group_arn.endswith(":*"):
        group_arn = group_arn[:-2]

    role_name = ctx.unique_name("sim2real-sqh-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "scheduled-query-exec"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:StartQuery", "logs:GetQueryResults", "logs:DescribeLogGroups"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    query_name = ctx.unique_name("sim2real-sq-history-")
    created_at_ms = int(time.time() * 1000)

    def _create():
        return logs.create_scheduled_query(
            name=query_name,
            queryLanguage="CWLI",
            queryString="fields @timestamp, @message | limit 10",
            scheduleExpression="cron(* * * * ? *)",
            executionRoleArn=role_arn,
            logGroupIdentifiers=[group_arn],
            state="ENABLED",
            startTimeOffset=60,
        )

    try:
        create_resp = _retry_on_code(_create, "ResourceNotFoundException", attempts=10, delay_s=3)
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"CreateScheduledQuery with a per-minute cron was rejected: {exc}") from exc
    sq_arn = create_resp["scheduledQueryArn"]
    ctx.on_cleanup(lambda: _safe_delete_query(logs, sq_arn))

    start_time = (created_at_ms // 1000) - 60
    deadline = time.monotonic() + 360
    history = []
    while time.monotonic() < deadline:
        end_time = int(time.time())
        resp = logs.get_scheduled_query_history(
            identifier=sq_arn, startTime=start_time, endTime=end_time
        )
        history = resp.get("triggerHistory", [])
        if history:
            break
        time.sleep(15)

    if not history:
        raise AssertionError(
            "no scheduled query execution landed in GetScheduledQueryHistory within the "
            "bounded test window; scheduling latency exceeded the budget"
        )

    entry = history[0]
    assert resp["name"] == query_name, f"GetScheduledQueryHistory name mismatch: expected {query_name!r}, got {resp['name']!r}"
    assert resp["scheduledQueryArn"] == sq_arn, (
        f"GetScheduledQueryHistory scheduledQueryArn mismatch: expected {sq_arn!r}, got {resp['scheduledQueryArn']!r}"
    )
    assert entry["executionStatus"] in ("Running", "Complete", "Failed", "Timeout", "InvalidQuery"), (
        f"unexpected executionStatus in trigger history entry: {entry['executionStatus']!r}"
    )


def _retry_on_code(fn, code: str, *, attempts: int = 5, delay_s: float = 2.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != code:
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _safe_delete_query(logs, sq_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.delete_scheduled_query(identifier=sq_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
