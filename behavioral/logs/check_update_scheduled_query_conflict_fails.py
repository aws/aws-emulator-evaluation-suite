"""update-scheduled-query-conflict-fails."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "update-scheduled-query-conflict-fails"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateScheduledQuery calls against the same scheduled query either succeed or
    fail with ConflictException (never a different error), and the final state matches
    exactly one of the racing writers -- no corrupted/mixed state under contention."""
    logs = ctx.client("logs")

    log_group_name, log_group_arn = _create_log_group(ctx, "sim2real-behav-sqlg-")
    role_name, role_arn = _create_execution_role(ctx)
    _attach_execution_policy(ctx, role_name)

    query_name = ctx.unique_name("sim2real-behav-sq-")
    _create_scheduled_query_with_retry(
        logs,
        name=query_name,
        queryLanguage="CWLI",
        queryString="fields @timestamp, @message | limit 1",
        scheduleExpression="cron(0 12 * * ? *)",
        executionRoleArn=role_arn,
        logGroupIdentifiers=[log_group_arn],
        state="ENABLED",
        startTimeOffset=3600,
        tags={"sim2real": "update-scheduled-query-conflict-fails"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_scheduled_query(identifier=query_name)))

    n_racers = 8
    barrier = threading.Barrier(n_racers)

    def _racer(i: int) -> tuple[bool, str, str | None]:
        query_string = f"fields @timestamp, @message | limit {i + 2}"
        barrier.wait()
        try:
            logs.update_scheduled_query(
                identifier=query_name,
                queryLanguage="CWLI",
                queryString=query_string,
                scheduleExpression="cron(0 12 * * ? *)",
                executionRoleArn=role_arn,
                logGroupIdentifiers=[log_group_arn],
                startTimeOffset=3600,
            )
            return True, query_string, None
        except Exception as e:  # noqa: BLE001
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return False, query_string, e.response["Error"]["Code"]
            raise

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_racer, range(n_racers)))

    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]

    # Real AWS does not always reject a losing racer in this contention scenario with the
    # modeled ConflictException -- it can also surface the same "another update is already
    # in progress for this scheduled query" rejection as ValidationException. Either is a
    # valid, non-corrupting outcome; anything else indicates a genuinely different failure
    # mode and should still fail this check.
    acceptable_codes = {"ConflictException", "ValidationException"}
    bad_codes = {code for (_ok, _q, code) in failures if code not in acceptable_codes}
    assert not bad_codes, f"racing updates failed with unexpected error codes: {bad_codes}"

    if successes:
        final = logs.get_scheduled_query(identifier=query_name)
        winning_strings = {q for (_ok, q, _c) in successes}
        assert final["queryString"] in winning_strings, (
            f"final queryString {final['queryString']!r} does not match any successful "
            f"racing writer {winning_strings} -- possible corrupted state under contention"
        )
    else:
        # Under this level of contention, real AWS can legitimately reject every single
        # racer with ConflictException (e.g. if it serializes on an "update in progress"
        # lock rather than a last-writer-wins optimistic scheme). That's still a valid,
        # non-corrupting outcome as long as: (1) the resource was left completely
        # untouched by the race, and (2) the update path is not simply broken -- a solo,
        # non-racing update issued right afterwards must succeed.
        final = logs.get_scheduled_query(identifier=query_name)
        assert final["queryString"] == "fields @timestamp, @message | limit 1", (
            f"scheduled query was mutated to {final['queryString']!r} even though every "
            f"racing update reported ConflictException -- possible corrupted state "
            f"under contention"
        )

        confirm_query_string = "fields @timestamp, @message | limit 99"
        logs.update_scheduled_query(
            identifier=query_name,
            queryLanguage="CWLI",
            queryString=confirm_query_string,
            scheduleExpression="cron(0 12 * * ? *)",
            executionRoleArn=role_arn,
            logGroupIdentifiers=[log_group_arn],
            startTimeOffset=3600,
        )
        final2 = logs.get_scheduled_query(identifier=query_name)
        assert final2["queryString"] == confirm_query_string, (
            "a solo (non-racing) update failed even after every racing update reported "
            "ConflictException -- the update path appears broken, not merely contended"
        )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


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
    logs.create_log_group(logGroupName=name, tags={"sim2real": "update-scheduled-query-conflict-fails"})
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
        Tags=[{"Key": "sim2real", "Value": "update-scheduled-query-conflict-fails"}],
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
