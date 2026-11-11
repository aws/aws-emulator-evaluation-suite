"""test-transformer-dry-run-does-not-mutate-stored-logs."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "test-transformer-dry-run-does-not-mutate-stored-logs"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestTransformer is a pure dry-run: it must never write its sample output into any
    real log group, even when a real transformer is already configured on that group."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-testtransformer-lg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    real_config = [
        {"parseJSON": {}},
        {"addKeys": {"entries": [{"key": "realField", "value": "real-value", "overwriteIfExists": True}]}},
    ]
    logs.put_transformer(logGroupIdentifier=log_group, transformerConfig=real_config)
    ctx.on_cleanup(lambda: logs.delete_transformer(logGroupIdentifier=log_group))

    # PutTransformer can take minutes before it applies to newly ingested
    # events.
    # Waiting for that activation to be observably reflected in transformed
    # output is therefore not a reliable (nor necessary) way to establish the
    # precondition this check actually needs.
    #
    # What this check is verifying is narrower and doesn't require the real
    # transformer to have already taken effect: whatever the stored state of
    # the log group is at the time TestTransformer is invoked (transformed or
    # not -- that is a orthogonal, separately-covered behavior), a dry-run
    # TestTransformer call must not change it. So capture the "before" state
    # as-is (with only a short poll for basic put/get eventual consistency,
    # not for transformer activation), then assert the stored state is
    # byte-for-byte identical after the dry run.
    stream = ctx.unique_name("sim2real-stream-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": '{"msg": "hello"}'}],
    )

    events = _poll_until(
        lambda: logs.get_log_events(
            logGroupName=log_group, logStreamName=stream, startFromHead=True
        )["events"],
        lambda evs: len(evs) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert len(events) == 1, f"expected exactly 1 stored event, got {len(events)}"
    before_message = events[0]["message"]

    dry_run_config = [
        {"parseJSON": {}},
        {
            "addKeys": {
                "entries": [
                    {"key": "dryRunField", "value": "dry-run-should-not-persist", "overwriteIfExists": True}
                ]
            }
        },
    ]
    test_resp = logs.test_transformer(
        transformerConfig=dry_run_config, logEventMessages=['{"msg": "other"}']
    )
    transformed = test_resp["transformedLogs"]
    assert any(
        "dryRunField" in t.get("transformedEventMessage", "") for t in transformed
    ), f"TestTransformer dry-run result did not apply the requested transform: {transformed}"

    # The dry run must not have touched the real log group's stored data: the
    # stored event must be byte-for-byte identical to what it was before the
    # dry run, regardless of whether the real transformer had (or had not yet)
    # taken effect on it.
    after = logs.get_log_events(
        logGroupName=log_group, logStreamName=stream, startFromHead=True
    )["events"]
    assert len(after) == 1, f"stored event count changed after TestTransformer dry-run: {len(after)}"
    assert after[0]["message"] == before_message, (
        "TestTransformer dry-run mutated the stored event: "
        f"before={before_message!r} after={after[0]['message']!r}"
    )
    assert "dryRunField" not in after[0]["message"], (
        f"TestTransformer dry-run output leaked into stored logs: {after[0]['message']!r}"
    )
    assert "dry-run-should-not-persist" not in after[0]["message"], (
        f"TestTransformer dry-run value leaked into stored logs: {after[0]['message']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
