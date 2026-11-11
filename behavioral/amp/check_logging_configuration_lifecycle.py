"""logging-configuration-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "logging-configuration-lifecycle"
GROUP = "deploy"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLoggingConfiguration wires a real CloudWatch Logs group to an AMP workspace
    (CREATING->ACTIVE), UpdateLoggingConfiguration repoints it to a second log group, and
    DeleteLoggingConfiguration removes the wiring."""
    amp = ctx.client("amp")
    logs = ctx.client("logs")

    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real:managed": "true"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    log_group_1 = ctx.unique_name("/sim2real/amp-logging-1-")
    logs.create_log_group(logGroupName=log_group_1, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_1))
    arn_1 = logs.describe_log_groups(logGroupNamePrefix=log_group_1)["logGroups"][0]["arn"]

    log_group_2 = ctx.unique_name("/sim2real/amp-logging-2-")
    logs.create_log_group(logGroupName=log_group_2, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_2))
    arn_2 = logs.describe_log_groups(logGroupNamePrefix=log_group_2)["logGroups"][0]["arn"]

    amp.create_logging_configuration(workspaceId=workspace_id, logGroupArn=arn_1)
    status = _poll_until(
        lambda: amp.describe_logging_configuration(workspaceId=workspace_id)["loggingConfiguration"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "CREATION_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"expected logging configuration ACTIVE after create, got {status!r}"
    described_arn = amp.describe_logging_configuration(workspaceId=workspace_id)["loggingConfiguration"]["logGroupArn"]
    assert described_arn == arn_1, f"expected logGroupArn {arn_1!r} after create, got {described_arn!r}"

    amp.update_logging_configuration(workspaceId=workspace_id, logGroupArn=arn_2)
    status = _poll_until(
        lambda: amp.describe_logging_configuration(workspaceId=workspace_id)["loggingConfiguration"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "UPDATE_FAILED"),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"expected logging configuration ACTIVE after update, got {status!r}"
    described_arn = amp.describe_logging_configuration(workspaceId=workspace_id)["loggingConfiguration"]["logGroupArn"]
    assert described_arn == arn_2, f"expected logGroupArn {arn_2!r} after update, got {described_arn!r}"

    amp.delete_logging_configuration(workspaceId=workspace_id)
    code, message = _error(lambda: amp.describe_logging_configuration(workspaceId=workspace_id), wait_s=120)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    expected = "Workspace logging configuration not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    update_after_delete, message = _error(
        lambda: amp.update_logging_configuration(workspaceId=workspace_id, logGroupArn=arn_1)
    )
    assert update_after_delete == "ResourceNotFoundException", (
        f"expected update on a deleted logging configuration to fail with ResourceNotFoundException, "
        f"got {update_after_delete!r}"
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
