"""partiql-update-returning-modified-images-on-nested-paths."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-update-returning-modified-images-on-nested-paths"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RETURNING MODIFIED NEW * / MODIFIED OLD * on an UPDATE SETting a nested map path and a
    list index return only the attribute whose addressed element existed on that side; a SET
    past a list's end appends the element but is absent from both, even alone.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbret-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    key = {"pk": {"S": "r1"}}
    ddb.put_item(
        TableName=table,
        Item={**key, "m": {"M": {"a": {"S": "orig_a"}}}, "l": {"L": [{"S": "x0"}, {"S": "x1"}]},
              "untouched": {"S": "same"}},
    )

    # 1. SET m.a (in-range) + SET l[5] (append past end, len=2) RETURNING MODIFIED NEW *: only
    # the nested map path is reported, since the list clause addressed an element that did not
    # exist on the new side's counterpart check below; untouched and the whole l are excluded.
    r1 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET m.a = ? SET l[5] = ? WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "new_a"}, {"S": "appended5"}, {"S": "r1"}],
    )["Items"]
    assert r1 == [{"m": {"M": {"a": {"S": "new_a"}}}}], (
        f"RETURNING MODIFIED NEW * after SET m.a + SET l[5] (append) returned {r1!r}"
    )
    stored1 = _stored(ddb, table, "r1")
    assert stored1["l"] == {"L": [{"S": "x0"}, {"S": "x1"}, {"S": "appended5"}]}, (
        f"the append must still have happened: l is {stored1.get('l')!r}"
    )
    assert stored1["untouched"] == {"S": "same"}, "an unrelated attribute must survive untouched"

    # 2. SET l[1] (in-range, replacing an existing element) RETURNING MODIFIED OLD * returns the
    # single pre-update element, wrapped as a one-element list, not the whole old list.
    r2 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET l[1] = ? WHERE pk = ? RETURNING MODIFIED OLD *',
        Parameters=[{"S": "replaced1"}, {"S": "r1"}],
    )["Items"]
    assert r2 == [{"l": {"L": [{"S": "x1"}]}}], (
        f"RETURNING MODIFIED OLD * after an in-range SET l[1] returned {r2!r}, expected the old x1"
    )
    stored2 = _stored(ddb, table, "r1")
    assert stored2["l"] == {"L": [{"S": "x0"}, {"S": "replaced1"}, {"S": "appended5"}]}, (
        f"stored list after SET l[1] is {stored2.get('l')!r}"
    )

    # 3. SET l[10] alone (append far past the end, len=3) RETURNING MODIFIED OLD *: the clause
    # addressed nothing that existed, so Items is empty — not a one-item answer with an empty map.
    r3 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET l[10] = ? WHERE pk = ? RETURNING MODIFIED OLD *',
        Parameters=[{"S": "farappend"}, {"S": "r1"}],
    )["Items"]
    assert r3 == [], f"RETURNING MODIFIED OLD * for an append-only SET returned {r3!r}, expected []"
    stored3 = _stored(ddb, table, "r1")
    assert stored3["l"] == {"L": [{"S": "x0"}, {"S": "replaced1"}, {"S": "appended5"}, {"S": "farappend"}]}, (
        f"the append must still land at the end: l is {stored3.get('l')!r}"
    )

    # 4. The same shape with MODIFIED NEW * instead of MODIFIED OLD *: still empty, even though
    # the new value plainly exists once stored.
    r4 = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET l[10] = ? WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "farappend2"}, {"S": "r1"}],
    )["Items"]
    assert r4 == [], f"RETURNING MODIFIED NEW * for an append-only SET returned {r4!r}, expected []"
    stored4 = _stored(ddb, table, "r1")
    assert stored4["l"] == {
        "L": [{"S": "x0"}, {"S": "replaced1"}, {"S": "appended5"}, {"S": "farappend"}, {"S": "farappend2"}]
    }, f"the second append must also land at the end: l is {stored4.get('l')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
