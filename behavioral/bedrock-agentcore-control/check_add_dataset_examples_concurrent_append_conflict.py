"""add-dataset-examples-concurrent-append-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-dataset-examples-concurrent-append-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]
#: A loser meets the dataset either mid-update or after the winner changed it.
_CONFLICT_MESSAGES = (
    "Dataset is not in a state that allows this operation: UPDATING",
    "Failed to update the resource as a concurrent request modified the resource. Retry the "
    "request after the other request has completed.",
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent AddDatasetExamples calls on one dataset never lose or merge a batch: each
    caller either adds its 2 examples or is refused with ConflictException, and the final count is
    the base plus 2 per accepted caller."""
    bac = ctx.client("bedrock-agentcore-control")

    dataset = bac.create_dataset(
        datasetName=_alnum_name(ctx, "sim2realds"),
        source={"inlineExamples": {"examples": [{"input": "seed-example"}]}},
        schemaType="THIRD_PARTY_EVALUATION_V1",
        tags={"env": "sim2real-test", "purpose": "add-dataset-examples-concurrent-append-conflict"},
    )
    dataset_id = dataset["datasetId"]
    ctx.on_cleanup(lambda: _delete_dataset(bac, dataset_id))
    _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 120),
    )
    base = bac.get_dataset(datasetId=dataset_id)
    assert base["status"] == "ACTIVE", f"dataset setup failed: {base}"
    base_count = base["exampleCount"]

    bac.create_dataset_version(datasetId=dataset_id)
    _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 120),
    )

    def _adder(tag):
        return lambda: bac.add_dataset_examples(
            datasetId=dataset_id,
            source={"inlineExamples": {"examples": [{"input": f"{tag}-0"}, {"input": f"{tag}-1"}]}},
        )

    results = _race([_adder("race-a"), _adder("race-b")])
    successes = [r[1] for r in results if r[0]]
    for ok, value in results:
        if not ok:
            code, message = value
            assert code == "ConflictException", f"undocumented AddDatasetExamples refusal: {code!r} ({message!r})"
            assert message in _CONFLICT_MESSAGES, f"ConflictException message {message!r}, expected one of {_CONFLICT_MESSAGES!r}"
    assert successes, f"both AddDatasetExamples callers were refused: {results}"
    for resp in successes:
        assert resp["addedCount"] == 2, f"an accepted AddDatasetExamples added {resp['addedCount']}, not 2"

    final = _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 120),
    )
    expected = base_count + 2 * len(successes)
    assert final["exampleCount"] == expected, (
        f"dataset example count is not base + accepted additions: base={base_count} "
        f"accepted={len(successes)} expected={expected} final={final['exampleCount']}"
    )


def _alnum_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _race(fns, timeout_s=60.0):
    results: list = [None] * len(fns)
    barrier = threading.Barrier(len(fns))

    def _wrap(i, fn):
        barrier.wait()
        try:
            return i, True, fn()
        except ClientError as exc:
            return i, False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


def _delete_dataset(bac, dataset_id, timeout_s=120.0):
    """Delete the dataset once it leaves UPDATING; only a missing dataset is tolerated."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bac.delete_dataset(datasetId=dataset_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
