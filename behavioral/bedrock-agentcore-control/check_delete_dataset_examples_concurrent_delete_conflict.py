"""delete-dataset-examples-concurrent-delete-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dataset-examples-concurrent-delete-conflict"
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
    """Two concurrent DeleteDatasetExamples calls with overlapping ids never corrupt the DRAFT: each
    batch is applied whole or refused whole (all-or-nothing), so the listing and count equal the
    seed minus exactly the accepted batches' ids."""
    bac = ctx.client("bedrock-agentcore-control")

    dataset = bac.create_dataset(
        datasetName=_alnum_name(ctx, "sim2realdsd"),
        source={"inlineExamples": {"examples": [{"input": "seed"}]}},
        schemaType="THIRD_PARTY_EVALUATION_V1",
        tags={"sim2real-check": CHECK},
    )
    dataset_id = dataset["datasetId"]
    ctx.on_cleanup(lambda: _delete_dataset(bac, dataset_id))
    _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 120),
    )
    setup = bac.get_dataset(datasetId=dataset_id)
    assert setup["status"] == "ACTIVE", f"dataset setup failed: {setup}"

    bac.create_dataset_version(datasetId=dataset_id)
    _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 120),
    )

    add_resp = bac.add_dataset_examples(
        datasetId=dataset_id,
        source={"inlineExamples": {"examples": [{"input": f"ex-{i}"} for i in range(4)]}},
    )
    example_ids = add_resp["exampleIds"]
    assert len(example_ids) == 4, f"expected 4 added example ids, got {example_ids}"
    _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 120),
    )
    base = bac.get_dataset(datasetId=dataset_id)
    base_count = base["exampleCount"]

    ids_a = example_ids[0:2]
    ids_b = example_ids[1:3]

    def _deleter(ids):
        return lambda: bac.delete_dataset_examples(datasetId=dataset_id, exampleIds=ids)

    # A loser refused for contention gets ConflictException; one applied after the winner names
    # an id already gone, and the documented all-or-nothing rule refuses its whole batch.
    results = _race([_deleter(ids_a), _deleter(ids_b)])
    accepted = []
    for (ok, value), ids in zip(results, (ids_a, ids_b)):
        if ok:
            assert value["deletedCount"] == 2, f"an accepted delete of {ids} removed {value['deletedCount']}, not 2"
            accepted.append(ids)
            continue
        code, message = value
        assert code in _LOSER_CODES, f"undocumented DeleteDatasetExamples refusal: {code!r} ({message!r})"
        if code == "ConflictException":
            assert message in _CONFLICT_MESSAGES, f"ConflictException message {message!r}, expected one of {_CONFLICT_MESSAGES!r}"
        else:
            assert isinstance(message, str) and message, f"{code} without a message: {results}"
    assert accepted, f"both DeleteDatasetExamples callers were refused: {results}"
    deleted_ids = {i for ids in accepted for i in ids}

    final = _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 120),
    )
    assert final["exampleCount"] == base_count - len(deleted_ids), (
        f"dataset example count is not base minus the accepted batches: base={base_count} "
        f"deleted={sorted(deleted_ids)} final={final['exampleCount']}"
    )

    listed_ids = {ex["exampleId"] for ex in _list_all_examples(bac, dataset_id)}
    assert not (deleted_ids & listed_ids), (
        f"deleted example ids are still visible via ListDatasetExamples: {deleted_ids & listed_ids}"
    )
    still_expected = set(example_ids) - deleted_ids
    assert still_expected <= listed_ids, (
        f"examples no accepted delete targeted went missing (a refused batch was partly applied): "
        f"{still_expected - listed_ids} (listed={listed_ids})"
    )


# ConflictException for contention; ResourceNotFoundException or ValidationException for the
# all-or-nothing refusal of a batch naming an id that is no longer in DRAFT.
_LOSER_CODES = ("ConflictException", "ResourceNotFoundException", "ValidationException")


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


def _list_all_examples(bac, dataset_id):
    examples = []
    next_token = None
    while True:
        kwargs = {"datasetId": dataset_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = bac.list_dataset_examples(**kwargs)
        examples.extend(resp["examples"])
        next_token = resp.get("nextToken")
        if not next_token:
            return examples


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
