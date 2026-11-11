"""partiql-update-set-remove-nested-map-and-list-paths."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-set-remove-nested-map-and-list-paths"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly succeeded where an error was required: {resp!r}")


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL UPDATE SET through a missing parent map is refused and writes nothing; once the
    parent exists, SET on a nested path, SET past a list's end (an append), REMOVE in range,
    REMOVE out of range (a no-op) and REMOVE on a nested path each leave the exact stored item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbupd-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    key = {"pk": {"S": "u1"}}
    ddb.put_item(TableName=table, Item={**key, "keep": {"S": "k"}})

    # 1. SET through a nested path whose parent map does not exist is refused, and writes nothing.
    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET m.a.b = ? WHERE pk = ?',
        Parameters=[{"S": "x"}, {"S": "u1"}],
    ))
    assert code == "ValidationException", f"SET through a missing parent map answered {code!r}"
    assert message == "The document path provided in the update expression is invalid for update", (
        f"refusal message was {message!r}"
    )
    after_refusal = _stored(ddb, table, "u1")
    assert after_refusal == {**key, "keep": {"S": "k"}}, (
        f"a refused SET must not auto-create the intermediate map; item is {after_refusal!r}"
    )

    # Positive control: once the parent map and the list exist, the identical nested SET succeeds.
    ddb.put_item(
        TableName=table,
        Item={**key, "keep": {"S": "k"}, "m": {"M": {"a": {"M": {"b": {"S": "orig"}}}}},
              "l": {"L": [{"S": "z0"}]}},
    )
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET m.a.b = ? WHERE pk = ?',
        Parameters=[{"S": "newb"}, {"S": "u1"}],
    )
    stored = _stored(ddb, table, "u1")
    assert stored["m"] == {"M": {"a": {"M": {"b": {"S": "newb"}}}}}, (
        f"SET m.a.b did not update the nested path, stored m is {stored.get('m')!r}"
    )
    assert stored["l"] == {"L": [{"S": "z0"}]}, f"SET m.a.b touched l unexpectedly: {stored.get('l')!r}"

    # 2. SET on a list index past the list's end (len=1, index=2) appends rather than erroring
    # or leaving a hole.
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET l[2] = ? WHERE pk = ?',
        Parameters=[{"S": "appended"}, {"S": "u1"}],
    )
    stored = _stored(ddb, table, "u1")
    assert stored["l"] == {"L": [{"S": "z0"}, {"S": "appended"}]}, (
        f"SET l[2] past the end gave {stored.get('l')!r}, expected an append to index 1"
    )

    # 3. REMOVE on the now in-range index 1 deletes the appended element.
    ddb.execute_statement(Statement=f'UPDATE "{table}" REMOVE l[1] WHERE pk = ?', Parameters=[{"S": "u1"}])
    stored = _stored(ddb, table, "u1")
    assert stored["l"] == {"L": [{"S": "z0"}]}, f"REMOVE l[1] gave {stored.get('l')!r}, expected [z0]"

    # 4. REMOVE on an out-of-range index (len=1, index=5) is a silent no-op, not an error.
    ddb.execute_statement(Statement=f'UPDATE "{table}" REMOVE l[5] WHERE pk = ?', Parameters=[{"S": "u1"}])
    stored = _stored(ddb, table, "u1")
    assert stored["l"] == {"L": [{"S": "z0"}]}, (
        f"REMOVE l[5] out of range changed the list to {stored.get('l')!r}; it must be a no-op"
    )

    # 5. REMOVE on a nested map path drops that key, leaving the parent map (empty, not absent).
    ddb.execute_statement(Statement=f'UPDATE "{table}" REMOVE m.a WHERE pk = ?', Parameters=[{"S": "u1"}])
    final = _stored(ddb, table, "u1")
    assert final == {**key, "keep": {"S": "k"}, "m": {"M": {}}, "l": {"L": [{"S": "z0"}]}}, (
        f"after REMOVE m.a the item is {final!r}, expected an empty map m and l untouched"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
