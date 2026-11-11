"""query-logging-configuration-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-logging-configuration-lifecycle"
GROUP = "cross-service"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQueryLoggingConfiguration wires a CloudWatch Logs destination with a QSP filter
    threshold to an AMP workspace, DescribeQueryLoggingConfiguration reflects it once ACTIVE,
    and DeleteQueryLoggingConfiguration removes it."""
    amp = ctx.client("amp")
    logs = ctx.client("logs")

    workspace_id = amp.create_workspace(alias=ctx.unique_name("sim2real-amp-ws-"))["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    log_group = ctx.unique_name("/sim2real/amp-query-logging-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]

    destination = {"cloudWatchLogs": {"logGroupArn": log_group_arn}, "filters": {"qspThreshold": 1000}}
    amp.create_query_logging_configuration(workspaceId=workspace_id, destinations=[destination])

    status = _poll_until(
        lambda: amp.describe_query_logging_configuration(workspaceId=workspace_id)["queryLoggingConfiguration"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "CREATION_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"expected query logging config to reach ACTIVE, got {status}"

    described = amp.describe_query_logging_configuration(workspaceId=workspace_id)["queryLoggingConfiguration"]
    actual_arn = described["destinations"][0]["cloudWatchLogs"]["logGroupArn"]
    assert actual_arn == log_group_arn, f"expected destination log group {log_group_arn}, got {actual_arn}"
    actual_threshold = described["destinations"][0]["filters"]["qspThreshold"]
    assert actual_threshold == 1000, f"expected qspThreshold 1000, got {actual_threshold}"

    amp.delete_query_logging_configuration(workspaceId=workspace_id)
    code, message = _error(lambda: amp.describe_query_logging_configuration(workspaceId=workspace_id), wait_s=120)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    expected = "Workspace logging configuration not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A mutation on the now-dead config also fails, not just the read.
    redelete_code, message = _error(lambda: amp.delete_query_logging_configuration(workspaceId=workspace_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-delete of a gone query logging config to fail with ResourceNotFoundException, got {redelete_code}"
    )
    expected = "Workspace logging configuration not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn, *, wait_s=0.0, interval_s=3.0):
    """Call fn(), which must fail; return its botocore error (code, message). With wait_s a
    success is retried until the refusal appears, and a success past the deadline raises, so a
    target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response["Error"]
            return error["Code"], error.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
