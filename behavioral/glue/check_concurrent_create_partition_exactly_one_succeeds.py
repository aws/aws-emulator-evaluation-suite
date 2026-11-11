"""concurrent-create-partition-exactly-one-succeeds."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-partition-exactly-one-succeeds"
GROUP = 'concurrency'
SERVICES = ['glue']


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of racing CreatePartition calls for the same values exactly one succeeds and the rest fail with
    AlreadyExistsException or ConcurrentModificationException; one partition is stored, at the winner's
    location.
    """
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(
        DatabaseInput={"Name": db_name},
        Tags={"sim2real-behav-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": "s3://example-bucket/data/",
            },
            "PartitionKeys": [{"Name": "dt", "Type": "string"}],
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    values = ["2024-04-01"]
    n = 5
    offered = {i: f"s3://example-bucket/data/dt=2024-04-01/writer-{i}/" for i in range(n)}

    def attempt(index):
        return glue.create_partition(
            DatabaseName=db_name,
            TableName=tbl_name,
            PartitionInput={
                "Values": values,
                "StorageDescriptor": {
                    "Columns": [{"Name": "col1", "Type": "string"}],
                    "Location": offered[index],
                },
            },
        )

    results = _run_concurrent([lambda i=i: attempt(i) for i in range(n)], timeout_s=90)

    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly 1 successful create, got {successes}"
    winner = next(i for i, r in enumerate(results) if not isinstance(r, BaseException))

    codes = _concurrent_error_codes(results)
    assert len(codes) == n - 1, f"expected {n - 1} failures, got {len(codes)}: {codes}"
    conflict_codes = {"AlreadyExistsException", "ConcurrentModificationException"}
    assert all(c in conflict_codes for c in codes), (
        f"every loser must get a conflict error from {sorted(conflict_codes)}, got {codes}"
    )
    for r in results:
        if isinstance(r, ClientError) and r.response["Error"]["Code"] == "AlreadyExistsException":
            message = r.response["Error"].get("Message")
            assert message == "Partition already exists.", message

    # Independent read at the destination: the mutating calls' own responses could all
    # claim success/conflict correctly and the catalog could still disagree.
    partitions = []
    for page in glue.get_paginator("get_partitions").paginate(
        DatabaseName=db_name, TableName=tbl_name
    ):
        partitions.extend(page["Partitions"])
    assert len(partitions) == 1, (
        f"expected exactly 1 stored partition for one set of values, got "
        f"{len(partitions)}: {[p['Values'] for p in partitions]}"
    )
    assert partitions[0]["Values"] == values, (
        f"stored partition values are {partitions[0]['Values']}, expected {values}"
    )
    stored_location = partitions[0]["StorageDescriptor"]["Location"]
    assert stored_location == offered[winner], (
        f"stored location {stored_location!r} does not match the winning thread "
        f"{winner}'s offer {offered[winner]!r} -- the catalog disagrees with the "
        f"winning create_partition response"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
