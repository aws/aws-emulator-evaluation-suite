"""put-log-events-concurrent-writers-all-accepted."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "put-log-events-concurrent-writers-all-accepted"
GROUP = "concurrency"
SERVICES = ["logs"]

NUM_WRITERS = 8
EVENTS_PER_WRITER = 5


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutLogEvents writers on the same stream all succeed with no rejected events, and the
    stream holds exactly every writer's events, none lost or duplicated.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-")
    stream = ctx.unique_name("sim2real-behav-ls-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    base_ms = int(time.time() * 1000)

    def write_batch(worker_id: int):
        events = [
            {
                "timestamp": base_ms + worker_id,
                "message": f"sim2real-worker-{worker_id}-event-{i}",
            }
            for i in range(EVENTS_PER_WRITER)
        ]
        resp = logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
        return worker_id, resp

    results = {}
    errors = {}
    with ThreadPoolExecutor(max_workers=NUM_WRITERS) as pool:
        futures = {pool.submit(write_batch, i): i for i in range(NUM_WRITERS)}
        for fut in as_completed(futures):
            worker_id = futures[fut]
            try:
                _, resp = fut.result()
                results[worker_id] = resp
            except Exception as e:  # noqa: BLE001 - we want to assert none happened
                errors[worker_id] = e

    assert not errors, f"concurrent PutLogEvents callers were rejected: {errors}"
    assert len(results) == NUM_WRITERS, (
        f"expected all {NUM_WRITERS} concurrent writers to return a response, "
        f"got {len(results)}: {sorted(results)}"
    )
    for worker_id, resp in results.items():
        assert resp.get("rejectedLogEventsInfo") is None, (
            f"worker {worker_id} batch was rejected: {resp.get('rejectedLogEventsInfo')}"
        )

    expected_total = NUM_WRITERS * EVENTS_PER_WRITER
    events = _wait_for_events(ctx, group, stream, expected_count=expected_total, timeout_s=45)
    messages = [e["message"] for e in events]
    assert len(messages) == expected_total, (
        f"expected exactly {expected_total} events across {NUM_WRITERS} concurrent writers, "
        f"found {len(messages)} (no loss/dup expected)"
    )
    assert len(set(messages)) == expected_total, "duplicate events detected under concurrency"
    expected_messages = {
        f"sim2real-worker-{w}-event-{i}" for w in range(NUM_WRITERS) for i in range(EVENTS_PER_WRITER)
    }
    assert set(messages) == expected_messages, (
        f"message set mismatch under concurrency: missing "
        f"{expected_messages - set(messages)}, unexpected {set(messages) - expected_messages}"
    )


def _wait_for_events(ctx, group, stream, expected_count, timeout_s=45.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events: list[dict] = []
    while time.monotonic() < deadline:
        events = []
        token = None
        while True:
            kwargs = {
                "logGroupName": group,
                "logStreamName": stream,
                "startFromHead": True,
            }
            if token is not None:
                kwargs["nextToken"] = token
            resp = logs.get_log_events(**kwargs)
            events.extend(resp["events"])
            new_token = resp.get("nextForwardToken")
            if new_token == token or not resp["events"]:
                break
            token = new_token
        if len(events) >= expected_count:
            return events
        time.sleep(1.5)
    raise AssertionError(f"expected {expected_count} events, saw {len(events)} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
