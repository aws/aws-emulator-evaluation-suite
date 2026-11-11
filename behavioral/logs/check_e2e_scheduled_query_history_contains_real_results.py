"""e2e-scheduled-query-history-contains-real-results."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-scheduled-query-history-contains-real-results"
GROUP = "e2e"
SERVICES = ["logs"]


# timing:real-time — schedule: 60 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A scheduled query against a populated log group actually executes on its cron schedule:
    GetScheduledQueryHistory records a Complete execution and GetQueryResults for that
    execution's queryId contains the real matching log data (not a fabricated/empty result)."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    log_group = ctx.unique_name("sim2real-behav-lg-")
    log_stream = ctx.unique_name("sim2real-behav-ls-")
    role_name = ctx.unique_name("sim2real-behav-sq-role-")
    query_name = ctx.unique_name("sim2real-behav-sq-")
    marker = f"sim2real-marker-{uuid.uuid4().hex}"

    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": now_ms, "message": f"ERROR {marker} request failed"}],
    )

    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "logs.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduled-query-exec",
        PolicyDocument=json.dumps(
            {
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
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="scheduled-query-exec")
    )

    creation_epoch_s = int(time.time())
    scheduled_arn = _create_scheduled_query_with_retry(
        ctx,
        name=query_name,
        query_string=f"fields @message | filter @message like /{marker}/",
        role_arn=role_arn,
        log_group=log_group,
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_scheduled_query(identifier=scheduled_arn)))

    record = _poll_for_completed_execution(
        ctx, scheduled_arn, start_epoch_s=creation_epoch_s - 60, timeout_s=360.0
    )
    assert record is not None, "scheduled query never recorded a Complete execution"

    results = logs.get_query_results(queryId=record["queryId"])
    assert results["status"] == "Complete", f"expected Complete, got {results['status']!r}"
    flat_values = {
        field["value"]
        for row in results["results"]
        for field in row
        if field.get("field") == "@message"
    }
    assert any(marker in value for value in flat_values), (
        f"scheduled query results {flat_values!r} do not contain the written marker {marker!r}"
    )

    logs.delete_scheduled_query(identifier=scheduled_arn)
    code, message = _error(lambda: logs.get_scheduled_query(identifier=scheduled_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetScheduledQuery after delete, got {code!r}"
    )
    assert message == f"Scheduled query with identifier {scheduled_arn} not found", (
        f"unexpected GetScheduledQuery message after delete: {message!r}"
    )


# ===== helpers =====
def _ignore_not_found(fn) -> None:
    """Run a teardown delete; an already-deleted resource is fine, any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_scheduled_query_with_retry(
    ctx, *, name: str, query_string: str, role_arn: str, log_group: str, timeout_s: float = 60.0
) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = logs.create_scheduled_query(
                name=name,
                queryLanguage="CWLI",
                queryString=query_string,
                scheduleExpression="cron(* * * * ? *)",
                executionRoleArn=role_arn,
                logGroupIdentifiers=[log_group],
                startTimeOffset=3600,
                endTimeOffset=0,
                state="ENABLED",
            )
            return resp["scheduledQueryArn"]
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] not in ("ValidationException", "AccessDeniedException"):
                raise
            time.sleep(3.0)
    raise AssertionError(f"CreateScheduledQuery never succeeded: {last_err}")


def _poll_for_completed_execution(ctx, scheduled_arn: str, start_epoch_s: int, timeout_s: float):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        history = logs.get_scheduled_query_history(
            identifier=scheduled_arn,
            startTime=start_epoch_s,
            endTime=int(time.time()) + 60,
        )
        for record in history.get("triggerHistory", []):
            if record.get("executionStatus") == "Complete":
                return record
        time.sleep(10.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
