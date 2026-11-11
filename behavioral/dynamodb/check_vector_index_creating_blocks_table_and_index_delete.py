"""vector-index-creating-blocks-table-and-index-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vector-index-creating-blocks-table-and-index-delete"
GROUP = "vector"
SERVICES = ["dynamodb"]

_INDEX = "late-euc"
#: AWS has been seen taking several minutes to settle a single-item vector index; the ceiling is
#: generous on purpose and never asserted as a duration.
_SETTLE_BUDGET_S = 1500


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Right after UpdateTable adds a vector index, DeleteTable and an UpdateTable deleting that
    index both raise ResourceInUseException with the exact message; once the index settles ACTIVE,
    DescribeTable no longer carries a Backfilling key, and DeleteTable then succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbvec-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # DeleteTable is refused while a vector index is being created, so a plain delete registered
    # here would leak the table whenever the check fails mid-allocation.
    ctx.on_cleanup(lambda: _delete_table_when_settled(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "only"}, "emb": {"L": _vec([0.0, 0.0, 0.0, 0.0])}})

    resp = ddb.update_table(
        TableName=table,
        VectorIndexUpdates=[
            {
                "Create": {
                    "IndexName": _INDEX,
                    "VectorAttribute": {"AttributeName": "emb"},
                    "Dimensions": 4,
                    "DistanceFunction": "EUCLIDEAN",
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )
    created = next(
        v for v in resp["TableDescription"].get("VectorIndexes") or [] if v.get("IndexName") == _INDEX
    )
    assert created.get("IndexStatus") == "CREATING", (
        f"a just-requested vector index must be CREATING, UpdateTable described {created!r}"
    )

    # Assert the refusals right away, with no wait: the allocation window itself is never pinned.
    delete_table_err = _error(lambda: ddb.delete_table(TableName=table), "DeleteTable")
    assert delete_table_err.get("Code") == "ResourceInUseException", (
        f"DeleteTable while the vector index is CREATING: expected ResourceInUseException, "
        f"got {delete_table_err!r}"
    )
    delete_table_msg = (
        "Attempt to change a resource which is still in use: Cannot delete table while "
        "indexes are being created, updated, or deleted."
    )
    assert delete_table_err.get("Message") == delete_table_msg, (
        f"DeleteTable while CREATING: expected message {delete_table_msg!r}, "
        f"got {delete_table_err.get('Message')!r}"
    )

    delete_index_err = _error(
        lambda: ddb.update_table(
            TableName=table, VectorIndexUpdates=[{"Delete": {"IndexName": _INDEX}}]
        ),
        "UpdateTable deleting the still-CREATING vector index",
    )
    assert delete_index_err.get("Code") == "ResourceInUseException", (
        f"deleting the vector index while it is CREATING: expected ResourceInUseException, "
        f"got {delete_index_err!r}"
    )
    delete_index_msg = (
        "Attempt to change a resource which is still in use: Index creation is in resource "
        "allocation phase. Retry deletion during backfilling phase or when the index is active. "
        f"Table: {table} Index: {_INDEX}"
    )
    assert delete_index_err.get("Message") == delete_index_msg, (
        f"deleting the vector index while CREATING: expected message {delete_index_msg!r}, "
        f"got {delete_index_err.get('Message')!r}"
    )

    # Both refusals must have left the table and its index untouched.
    after_refusals = ddb.describe_table(TableName=table)["Table"]
    names = [v.get("IndexName") for v in after_refusals.get("VectorIndexes") or []]
    assert names == [_INDEX], (
        f"the refused deletes must leave exactly the vector index {_INDEX!r}, got {names!r}"
    )

    final = _poll_to_active(ddb, table)
    assert "Backfilling" not in final, (
        f"an ACTIVE vector index must not carry a Backfilling key, got {final!r}"
    )

    # Positive control: once ACTIVE, DeleteTable succeeds normally.
    ddb.delete_table(TableName=table)
    _wait_table_deleted(ddb, table)
    gone = _error(lambda: ddb.describe_table(TableName=table), "DescribeTable after delete")
    assert gone.get("Code") == "ResourceNotFoundException", gone
    gone_msg = f"Requested resource not found: Table: {table} not found"
    assert gone.get("Message") == gone_msg, (
        f"expected message {gone_msg!r}, got {gone.get('Message')!r}"
    )


def _vec(values):
    return [{"N": repr(float(x))} for x in values]


def _error(call, what):
    """The service error ``call`` raises, as its Error dict; an unexpected success raises."""
    try:
        result = call()
    except Exception as exc:  # noqa: BLE001 -- the code IS the assertion
        err = (getattr(exc, "response", None) or {}).get("Error")
        if not err:
            raise AssertionError(f"{what}: raised a non-service error {exc!r}") from exc
        return err
    raise AssertionError(f"{what}: the call was accepted, expected a refusal; got {result!r}")


def _poll_to_active(ddb, table, timeout_s=_SETTLE_BUDGET_S):
    """Poll DescribeTable to the vector index's terminal ACTIVE state and return its description."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        tbl = ddb.describe_table(TableName=table)["Table"]
        cur = [v for v in tbl.get("VectorIndexes") or [] if v.get("IndexName") == _INDEX]
        assert cur, f"the vector index vanished while being created: {tbl.get('VectorIndexes')!r}"
        last = cur[0]
        if last.get("IndexStatus") == "ACTIVE" and tbl["TableStatus"] == "ACTIVE":
            return last
        time.sleep(2)
    raise AssertionError(f"the vector index never became ACTIVE within {timeout_s}s: {last!r}")


def _wait_table_deleted(ddb, table, timeout_s=90):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            ddb.describe_table(TableName=table)
        except Exception as exc:  # noqa: BLE001
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(1)
    raise AssertionError(f"table {table} was not deleted within {timeout_s}s")


def _delete_table_when_settled(ddb, table, timeout_s=_SETTLE_BUDGET_S):
    deadline = time.time() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except Exception as exc:  # noqa: BLE001
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.time() > deadline:
                raise
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
