"""concurrent-put-lookup-table-rows-last-writer-wins-deterministically."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-lookup-table-rows-last-writer-wins-deterministically"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateLookupTable is a full-content-replacement operation with no locking.
    Concurrent writers racing on the same lookup table must converge to exactly one
    racer's full payload -- never a merge, truncation, or interleaved/corrupted mix."""
    logs = ctx.client("logs")
    table_name = ctx.unique_name("sim2real-behav-lut-").replace("-", "_")
    initial_body = "key,value\nseed,0\n"
    created = logs.create_lookup_table(lookupTableName=table_name, tableBody=initial_body)
    table_arn = created["lookupTableArn"]
    ctx.on_cleanup(lambda: logs.delete_lookup_table(lookupTableArn=table_arn))

    # Each racer writes a distinct, fully-formed, single-row CSV body.
    bodies = {f"racer-{i}": f"key,value\nrow,racer-{i}\n" for i in range(4)}

    def _write(body: str) -> None:
        logs.update_lookup_table(lookupTableArn=table_arn, tableBody=body)

    with ThreadPoolExecutor(max_workers=len(bodies)) as pool:
        futures = [pool.submit(_write, body) for body in bodies.values()]
        for f in futures:
            f.result()  # every concurrent write must be accepted -- none should error

    final_body = _poll_lookup_table_body(ctx, table_arn, set(bodies.values()))
    matching = [marker for marker, body in bodies.items() if body == final_body]
    assert len(matching) == 1, (
        f"final lookup table content did not exactly equal one racer's payload "
        f"(merge/corruption suspected): {final_body!r}"
    )


def _poll_lookup_table_body(
    ctx, table_arn: str, candidates: set[str], timeout_s: float = 30.0, interval_s: float = 1.0
) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_seen = ""
    while time.monotonic() < deadline:
        last_seen = logs.get_lookup_table(lookupTableArn=table_arn)["tableBody"]
        if last_seen in candidates:
            return last_seen
        time.sleep(interval_s)
    raise AssertionError(
        f"lookup table content never settled to one of the racers' payloads; last seen: {last_seen!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
