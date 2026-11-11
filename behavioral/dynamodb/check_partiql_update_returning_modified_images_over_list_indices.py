"""partiql-update-returning-modified-images-over-list-indices."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-returning-modified-images-over-list-indices"
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
    """UPDATE RETURNING MODIFIED * over list indices: several SET indices return a dense,
    ascending list regardless of SET order; SET at the list length appends (NEW carries it, OLD
    is empty); REMOVE of an index returns it under OLD and the shifted-in element under NEW.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqllistidx-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    # 1. A single non-zero index: MODIFIED NEW * carries only that element.
    _reset(ddb, table, "r1", ["a", "b", "c"])
    r = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[2] = ? WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "y"}, {"S": "r1"}],
    )["Items"]
    assert r == [{"tags": {"L": [{"S": "y"}]}}], f"SET tags[2] MODIFIED NEW * returned {r!r}"
    assert _stored(ddb, table, "r1")["tags"] == {"L": [{"S": "a"}, {"S": "b"}, {"S": "y"}]}, (
        f"stored tags after SET tags[2] is {_stored(ddb, table, 'r1')['tags']!r}"
    )

    # 2. Several indices, SET in descending index order: MODIFIED NEW * is still dense and
    # ascending by index, not in SET order.
    _reset(ddb, table, "r1", ["a", "b", "c"])
    r = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[2] = ? SET tags[0] = ? WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "y"}, {"S": "x"}, {"S": "r1"}],
    )["Items"]
    assert r == [{"tags": {"L": [{"S": "x"}, {"S": "y"}]}}], (
        f"SET tags[2] then tags[0] MODIFIED NEW * returned {r!r}, expected ascending index order"
    )
    assert _stored(ddb, table, "r1")["tags"] == {"L": [{"S": "x"}, {"S": "b"}, {"S": "y"}]}, (
        f"stored tags after the two SETs is {_stored(ddb, table, 'r1')['tags']!r}"
    )

    # 3. SET at exactly the list length appends: NEW returns the appended element, OLD returns [].
    _reset(ddb, table, "r1", ["a", "b", "c"])
    r_new = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[3] = ? WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "d"}, {"S": "r1"}],
    )["Items"]
    assert r_new == [{"tags": {"L": [{"S": "d"}]}}], f"SET tags[3] (append) MODIFIED NEW * returned {r_new!r}"
    r_old = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[4] = ? WHERE pk = ? RETURNING MODIFIED OLD *',
        Parameters=[{"S": "e"}, {"S": "r1"}],
    )["Items"]
    assert r_old == [], f"SET tags[4] (append) MODIFIED OLD * returned {r_old!r}, expected []"
    assert _stored(ddb, table, "r1")["tags"] == {
        "L": [{"S": "a"}, {"S": "b"}, {"S": "c"}, {"S": "d"}, {"S": "e"}]
    }, f"stored tags after the two appends is {_stored(ddb, table, 'r1')['tags']!r}"

    # 4. REMOVE tags[1] returns the removed element under OLD and the shifted-in element under NEW.
    _reset(ddb, table, "r1", ["a", "b", "c"])
    r_old = ddb.execute_statement(
        Statement=f'UPDATE "{table}" REMOVE tags[1] WHERE pk = ? RETURNING MODIFIED OLD *',
        Parameters=[{"S": "r1"}],
    )["Items"]
    assert r_old == [{"tags": {"L": [{"S": "b"}]}}], f"REMOVE tags[1] MODIFIED OLD * returned {r_old!r}"
    assert _stored(ddb, table, "r1")["tags"] == {"L": [{"S": "a"}, {"S": "c"}]}, (
        f"stored tags after REMOVE tags[1] is {_stored(ddb, table, 'r1')['tags']!r}"
    )

    _reset(ddb, table, "r1", ["a", "b", "c"])
    r_new = ddb.execute_statement(
        Statement=f'UPDATE "{table}" REMOVE tags[1] WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "r1"}],
    )["Items"]
    assert r_new == [{"tags": {"L": [{"S": "c"}]}}], (
        f"REMOVE tags[1] MODIFIED NEW * returned {r_new!r}, expected the shifted-in element"
    )

    # 5. REMOVE of the last index returns Items [] under NEW, because there is no element left
    # at that position to report.
    _reset(ddb, table, "r1", ["a", "b"])
    r_new = ddb.execute_statement(
        Statement=f'UPDATE "{table}" REMOVE tags[1] WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "r1"}],
    )["Items"]
    assert r_new == [], f"REMOVE of the last index MODIFIED NEW * returned {r_new!r}, expected []"
    assert _stored(ddb, table, "r1")["tags"] == {"L": [{"S": "a"}]}, (
        f"stored tags after removing the last index is {_stored(ddb, table, 'r1')['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
