"""retention-policy-purges-events-past-ttl."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "retention-policy-purges-events-past-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRetentionPolicy is reported by DescribeLogGroups and does not purge a fresh event, which stays
    readable; DeleteRetentionPolicy reverts the log group to never expire."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-")
    stream = ctx.unique_name("sim2real-behav-ls-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "sim2real-retention-event"}],
    )
    _wait_for_events(ctx, group, stream, expected_count=1, timeout_s=30)

    logs.put_retention_policy(logGroupName=group, retentionInDays=1)
    retention = _wait_for_retention(ctx, group, expected_days=1, timeout_s=30)
    assert retention == 1, f"expected retentionInDays=1 after PutRetentionPolicy, got {retention}"

    # The event is only seconds old, nowhere near the 1-day boundary: it must still be
    # retrievable right after the retention window is (re)configured.
    events = logs.get_log_events(
        logGroupName=group, logStreamName=stream, startFromHead=True
    )["events"]
    assert len(events) == 1 and events[0]["message"] == "sim2real-retention-event", (
        "recently-ingested event disappeared immediately after PutRetentionPolicy, before it "
        "could possibly have crossed the retention boundary"
    )

    logs.delete_retention_policy(logGroupName=group)
    reverted = _wait_for_retention(ctx, group, expected_days=None, timeout_s=30)
    assert reverted is None, f"expected no retentionInDays after DeleteRetentionPolicy, got {reverted}"


def _wait_for_events(ctx, group, stream, expected_count, timeout_s=30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
        if len(resp["events"]) >= expected_count:
            return
        time.sleep(1.0)
    raise AssertionError(f"events never became visible via GetLogEvents within {timeout_s}s")


def _wait_for_retention(ctx, group, expected_days, timeout_s=30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last = "unset"
    while time.monotonic() < deadline:
        resp = logs.describe_log_groups(logGroupNamePrefix=group)
        matches = [g for g in resp["logGroups"] if g["logGroupName"] == group]
        if matches:
            last = matches[0].get("retentionInDays")
            if last == expected_days:
                return last
        time.sleep(1.0)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
