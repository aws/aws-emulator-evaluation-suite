"""partiql-update-returning-modified-old-images-over-list-indices."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-returning-modified-old-images-over-list-indices"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


def _reset(ddb, table, pk, tags_list):
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": pk}, "tags": {"L": [{"S": v} for v in tags_list]}},
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATE RETURNING MODIFIED OLD * over list indices: REMOVE of the last index returns the
    removed element; several SET indices return their prior values, dense and in ascending
    index order regardless of SET order.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqllistidxold-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    # 1. REMOVE of the LAST index: MODIFIED OLD * returns the removed element itself.
    _reset(ddb, table, "r1", ["a", "b", "c"])
    r_old = ddb.execute_statement(
        Statement=f'UPDATE "{table}" REMOVE tags[2] WHERE pk = ? RETURNING MODIFIED OLD *',
        Parameters=[{"S": "r1"}],
    )["Items"]
    assert r_old == [{"tags": {"L": [{"S": "c"}]}}], (
        f"REMOVE of the last index MODIFIED OLD * returned {r_old!r}, expected the removed element"
    )
    assert _stored(ddb, table, "r1")["tags"] == {"L": [{"S": "a"}, {"S": "b"}]}, (
        f"stored tags after removing the last index is {_stored(ddb, table, 'r1')['tags']!r}"
    )

    # 2. Several indices, SET in descending index order: MODIFIED OLD * returns the PRIOR values,
    # dense and in ascending index order, not SET order.
    _reset(ddb, table, "r1", ["a", "b", "c"])
    r_old = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[2] = ? SET tags[0] = ? WHERE pk = ? RETURNING MODIFIED OLD *',
        Parameters=[{"S": "y"}, {"S": "x"}, {"S": "r1"}],
    )["Items"]
    assert r_old == [{"tags": {"L": [{"S": "a"}, {"S": "c"}]}}], (
        f"SET tags[2] then tags[0] MODIFIED OLD * returned {r_old!r}, "
        "expected prior values in ascending index order"
    )
    assert _stored(ddb, table, "r1")["tags"] == {"L": [{"S": "x"}, {"S": "b"}, {"S": "y"}]}, (
        f"stored tags after the two SETs is {_stored(ddb, table, 'r1')['tags']!r}"
    )

    # 3. Three non-contiguous indices SET out of order: MODIFIED OLD * still packs the prior
    # values densely and in ascending index order.
    _reset(ddb, table, "r2", ["a", "b", "c", "d"])
    r_old = ddb.execute_statement(
        Statement=(
            f'UPDATE "{table}" SET tags[3] = ? SET tags[0] = ? SET tags[1] = ? '
            "WHERE pk = ? RETURNING MODIFIED OLD *"
        ),
        Parameters=[{"S": "w"}, {"S": "x"}, {"S": "y"}, {"S": "r2"}],
    )["Items"]
    assert r_old == [{"tags": {"L": [{"S": "a"}, {"S": "b"}, {"S": "d"}]}}], (
        f"SET tags[3], tags[0], tags[1] MODIFIED OLD * returned {r_old!r}, "
        "expected the three prior values in ascending index order"
    )
    assert _stored(ddb, table, "r2")["tags"] == {
        "L": [{"S": "x"}, {"S": "y"}, {"S": "c"}, {"S": "w"}]
    }, f"stored tags after the three SETs is {_stored(ddb, table, 'r2')['tags']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
