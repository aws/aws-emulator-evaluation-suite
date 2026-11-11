"""vector-index-creating-blocks-other-index-but-accepts-self-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vector-index-creating-blocks-other-index-but-accepts-self-delete"
GROUP = "vector"
SERVICES = ["dynamodb"]

_N_ITEMS = 40


def _vec(values):
    return [{"N": repr(float(x))} for x in values]


def _error(fn, what: str):
    """The Error dict a rejected call raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if not err:
            raise AssertionError(f"{what}: raised with no Error body: {exc!r}") from exc
        return err
    raise AssertionError(f"{what}: the call was accepted, expected a refusal: {result!r}")


def _delete_table_when_settled(ddb, table, timeout_s=600):
    deadline = time.time() + timeout_s

    def run_undo() -> None:
        while True:
            try:
                ddb.delete_table(TableName=table)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.time() > deadline:
                    raise
            time.sleep(2)

    return run_undo


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a vector index is being created, UpdateTable adding a second vector index is refused
    with LimitExceededException; once the first leaves resource allocation, deleting it is accepted
    and the index disappears.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-vlc-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_delete_table_when_settled(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for i in range(_N_ITEMS):
        ddb.put_item(TableName=table, Item={"pk": {"S": f"item-{i:03d}"}, "emb": {"L": _vec([1.0, 0.0, 0.0, 0.0])}})
    scanned = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
    assert scanned == _N_ITEMS, f"expected {_N_ITEMS} items before adding the index, got {scanned}"

    add_resp = ddb.update_table(
        TableName=table,
        VectorIndexUpdates=[
            {
                "Create": {
                    "IndexName": "vidx-a",
                    "VectorAttribute": {"AttributeName": "emb"},
                    "Dimensions": 4,
                    "DistanceFunction": "EUCLIDEAN",
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )
    added = {v["IndexName"]: v for v in add_resp["TableDescription"].get("VectorIndexes", [])}
    assert set(added) == {"vidx-a"}, f"UpdateTable described indexes {sorted(added)}, expected only vidx-a"
    assert added["vidx-a"]["IndexStatus"] == "CREATING", (
        f"a just-requested vector index must be CREATING, was {added['vidx-a']['IndexStatus']!r}"
    )

    # Immediately: a second UpdateTable touching a DIFFERENT vector index while vidx-a builds.
    err = _error(
        lambda: ddb.update_table(
            TableName=table,
            VectorIndexUpdates=[
                {
                    "Create": {
                        "IndexName": "vidx-b",
                        "VectorAttribute": {"AttributeName": "emb"},
                        "Dimensions": 4,
                        "DistanceFunction": "COSINE",
                        "Projection": {"ProjectionType": "ALL"},
                    }
                }
            ],
        ),
        "UpdateTable adding vidx-b while vidx-a is building",
    )
    assert err.get("Code") == "LimitExceededException", (
        f"expected LimitExceededException, got {err.get('Code')!r} ({err.get('Message')!r})"
    )
    expected_msg = (
        "Subscriber limit exceeded: Only 1 online index can be created or deleted "
        "simultaneously per table"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )
    after_refusal = ddb.describe_table(TableName=table)["Table"]
    names_after_refusal = sorted(v["IndexName"] for v in after_refusal.get("VectorIndexes", []))
    assert names_after_refusal == ["vidx-a"], (
        f"a refused add must leave the index set unchanged, got {names_after_refusal!r}"
    )

    # Deleting vidx-a is refused while it is in resource allocation, so wait until DescribeTable
    # reports it Backfilling or ACTIVE before the self-delete.
    alloc_deadline = time.monotonic() + 600
    while True:
        vidx = next(
            v for v in ddb.describe_table(TableName=table)["Table"].get("VectorIndexes", [])
            if v["IndexName"] == "vidx-a"
        )
        if vidx.get("Backfilling") is True or vidx.get("IndexStatus") == "ACTIVE":
            break
        assert time.monotonic() < alloc_deadline, f"vidx-a never left resource allocation: {vidx!r}"
        time.sleep(2)

    delete_resp = ddb.update_table(
        TableName=table,
        VectorIndexUpdates=[{"Delete": {"IndexName": "vidx-a"}}],
    )
    deleted = {
        v["IndexName"]: v for v in delete_resp["TableDescription"].get("VectorIndexes", [])
    }
    assert set(deleted) == {"vidx-a"}, (
        f"UpdateTable self-delete described indexes {sorted(deleted)}, expected only vidx-a"
    )
    assert deleted["vidx-a"]["IndexStatus"] == "DELETING", (
        f"a just-accepted self-delete must report vidx-a DELETING, got "
        f"{deleted['vidx-a']['IndexStatus']!r}"
    )

    deadline = time.time() + 600
    final = None
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)["Table"]
        vidxs = tbl.get("VectorIndexes", [])
        if not vidxs and tbl["TableStatus"] == "ACTIVE":
            final = tbl
            break
        time.sleep(2)
    assert final is not None, (
        f"vidx-a was never fully removed within 600s; last seen "
        f"{ddb.describe_table(TableName=table)['Table'].get('VectorIndexes')!r}"
    )

    code_after = _error(
        lambda: ddb.search_vectors(
            TableName=table, IndexName="vidx-a", TopK=3, SearchVector=_vec([1.0, 0.0, 0.0, 0.0])
        ),
        "SearchVectors against the now-deleted vidx-a",
    )
    assert code_after.get("Code") == "ValidationException", (
        f"expected ValidationException searching deleted vidx-a, got {code_after.get('Code')!r}"
    )
    expected_search_msg = "The table does not have the specified index: vidx-a"
    assert code_after.get("Message") == expected_search_msg, (
        f"expected message {expected_search_msg!r}, got {code_after.get('Message')!r}"
    )

    scanned_after = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
    assert scanned_after == _N_ITEMS, (
        f"the base table lost items across the index lifecycle: expected {_N_ITEMS}, got {scanned_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
