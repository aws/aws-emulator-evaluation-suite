"""update-dataset-concurrent-version-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-dataset-concurrent-version-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataset raced against CreateDatasetVersion on one dataset: each call either takes
    effect or is refused with ConflictException, and the dataset shows exactly the accepted calls'
    effects (description set, one more version) and none of a refused call's."""
    bac = ctx.client("bedrock-agentcore-control")

    dataset = bac.create_dataset(
        datasetName=_alnum_name(ctx, "sim2realdsv"),
        source={"inlineExamples": {"examples": [{"input": "seed"}]}},
        schemaType="THIRD_PARTY_EVALUATION_V1",
        tags={"sim2real": CHECK},
    )
    dataset_id = dataset["datasetId"]
    ctx.on_cleanup(lambda: _delete_dataset(bac, dataset_id))
    _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 120),
    )
    setup_status = bac.get_dataset(datasetId=dataset_id)["status"]
    assert setup_status == "ACTIVE", f"dataset setup failed: expected ACTIVE, got {setup_status}"
    versions_before = len(bac.list_dataset_versions(datasetId=dataset_id)["versions"])

    def _update():
        return bac.update_dataset(datasetId=dataset_id, description="concurrent-update")

    def _version():
        return bac.create_dataset_version(datasetId=dataset_id)

    results = _race([_update, _version])
    for ok, value in results:
        if not ok:
            code, message = value
            assert code == "ConflictException", f"undocumented refusal in the race: {code!r} ({message!r})"
            assert isinstance(message, str) and message, f"ConflictException without a message: {results}"
    update_ok, version_ok = results[0][0], results[1][0]
    assert update_ok or version_ok, f"both UpdateDataset and CreateDatasetVersion were refused: {results}"

    final = _poll_until(
        lambda: bac.get_dataset(datasetId=dataset_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 120),
    )
    versions_after = len(bac.list_dataset_versions(datasetId=dataset_id)["versions"])

    if update_ok:
        assert final.get("description") == "concurrent-update", f"accepted UpdateDataset was not applied: {final}"
    else:
        assert final.get("description") != "concurrent-update", f"refused UpdateDataset was applied anyway: {final}"
    expected_versions = versions_before + (1 if version_ok else 0)
    assert versions_after == expected_versions, (
        f"version count does not match the accepted CreateDatasetVersion calls: before={versions_before} "
        f"version_accepted={version_ok} after={versions_after}"
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
