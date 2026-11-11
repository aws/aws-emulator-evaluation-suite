"""glue-concurrent-create-partition-lets-exactly-one-win-and-the-losers-see-already-exists."""
from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-concurrent-create-partition-lets-exactly-one-win-and-the-losers-see-already-exists"
GROUP = 'catalog-concurrency'
SERVICES = ['glue']

_THREADS = 6
_VALUES = ["2024-04-01"]


@tags("axis:happy-path", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Six threads racing CreatePartition for one partition: one wins, the rest get AlreadyExists.

    Exactly one partition remains and it holds the winner's location, not a merge or last writer's.
    """
    glue = ctx.client("glue")

    database = ctx.unique_name("sim2real_behav_gluedb_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_database(Name=database),
                                         f"glue database {database}"))

    table = ctx.unique_name("sim2real_behav_gluetbl_").replace("-", "_")
    base = f"s3://sim2real-behav-glue-nonexistent/{table}/"
    glue.create_table(DatabaseName=database, TableInput={
        "Name": table,
        "StorageDescriptor": {"Columns": [{"Name": "payload", "Type": "string"}],
                              "Location": base},
        "PartitionKeys": [{"Name": "dt", "Type": "string"}]})
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_table(DatabaseName=database, Name=table),
        f"glue table {database}.{table}"))
    # Registered before the race, so a partition created by ANY thread is undone even if an
    # assertion below aborts first.
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: glue.delete_partition(DatabaseName=database, TableName=table,
                                      PartitionValues=_VALUES),
        f"glue partition {database}.{table} {_VALUES}"))

    # Distinct locations identify the winner; which thread wins is not guaranteed, so not asserted.
    offered = {i: f"{base}dt={_VALUES[0]}/writer-{i}/" for i in range(_THREADS)}

    def attempt(index: int):
        return glue.create_partition(DatabaseName=database, TableName=table, PartitionInput={
            "Values": _VALUES,
            "StorageDescriptor": {"Columns": [{"Name": "payload", "Type": "string"}],
                                  "Location": offered[index]}})

    outcomes = {}
    losers = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as pool:
        futures = {pool.submit(attempt, i): i for i in range(_THREADS)}
        for future in concurrent.futures.as_completed(futures, timeout=120):
            index = futures[future]
            try:
                future.result()
                outcomes[index] = None
            except Exception as exc:  # noqa: BLE001 - the code is the observation
                outcomes[index] = _exception_code(exc)
                losers.append(exc)

    winners = sorted(i for i, code in outcomes.items() if code is None)
    loser_codes = [code for code in outcomes.values() if code is not None]
    loser_messages = {getattr(e, "response", {}).get("Error", {}).get("Message") for e in losers}

    partitions = []
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database,
                                                            TableName=table):
        partitions.extend(page["Partitions"])

    assert len(outcomes) == _THREADS, (
        f"only {len(outcomes)!r} of {_THREADS!r} threads reported an outcome: {outcomes!r}"
    )
    assert len(winners) == 1, (
        f"{len(winners)!r} of {_THREADS!r} concurrent create_partition calls succeeded "
        f"(threads {winners!r}); outcomes were {outcomes!r}"
    )
    assert set(loser_codes) == {"AlreadyExistsException"}, (
        f"loser codes were {sorted(set(loser_codes))!r}, expected only "
        f"AlreadyExistsException"
    )
    assert loser_messages == {"Partition already exists."}, (
        f"loser messages were {sorted(set(map(str, loser_messages)))!r}, expected only "
        f"'Partition already exists.'"
    )
    assert len(partitions) == 1, (
        f"the table holds {len(partitions)!r} partitions for one set of values: "
        f"{[p['Values'] for p in partitions]!r}"
    )
    stored = partitions[0]["StorageDescriptor"]["Location"]
    assert stored == offered[winners[0]], (
        f"the stored location is {stored!r}, not the winning thread {winners[0]!r}'s "
        f"{offered[winners[0]]!r}"
    )
    assert stored in set(offered.values()), (
        f"the stored location {stored!r} was offered by no thread; the six offers were "
        f"{sorted(offered.values())!r}"
    )
    assert partitions[0]["Values"] == _VALUES, (
        f"the surviving partition's values are {partitions[0]['Values']!r}, expected "
        f"{_VALUES!r}"
    )


def _exception_code(exc: BaseException) -> str:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"<{type(exc).__name__}: {exc}>"


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry so a throttled or dependency-blocked delete does not leak."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "ResourceNotFoundException")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
