"""update-set-arithmetic-and-list-append-type-mismatch-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-set-arithmetic-and-list-append-type-mismatch-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where an error was required: {resp!r}")


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


_TYPE_MISMATCH = "An operand in the update expression has an incorrect data type"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """UpdateItem arithmetic or list_append against an attribute of the wrong stored type is
    rejected with ValidationException and leaves the item unchanged; a same-typed operation
    on a sibling attribute still applies.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {
        **key,
        "word": {"S": "hello"},
        "props": {"M": {"depth": {"N": "1"}}},
        "tags": {"NS": ["1", "2"]},
        "n": {"N": "10"},
        "history": {"L": [{"S": "a"}]},
    }
    ddb.put_item(TableName=table, Item=original)

    # SET on a String attribute using "+" arithmetic: the operand's own type is a String.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET word = word + :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"SET word = word + :one with word stored as S answered {code!r} ({message!r}), "
        f"expected ValidationException"
    )
    assert message == _TYPE_MISMATCH, (
        f"SET word = word + :one refusal message is {message!r}, expected {_TYPE_MISMATCH!r}"
    )

    # SET on a Map attribute using "-" arithmetic: the operand's own type is a Map.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET props = props - :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"SET props = props - :one with props stored as M answered {code!r} ({message!r}), "
        f"expected ValidationException"
    )
    assert message == _TYPE_MISMATCH, (
        f"SET props = props - :one refusal message is {message!r}, expected {_TYPE_MISMATCH!r}"
    )

    # list_append requires List operands; the stored attribute is a Number Set.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET tags = list_append(tags, :more)",
        ExpressionAttributeValues={":more": {"L": [{"N": "3"}]}},
    ))
    assert code == "ValidationException", (
        f"list_append(tags, :more) with tags stored as NS answered {code!r} ({message!r}), "
        f"expected ValidationException"
    )
    assert message == _TYPE_MISMATCH, (
        f"list_append(tags, :more) refusal message is {message!r}, expected {_TYPE_MISMATCH!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after three refused type-mismatched updates the item is {unchanged!r}, expected it "
        f"unchanged from {original!r}"
    )

    # Positive controls: the identical operation against a same-typed sibling attribute applies.
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET n = n + :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"n": {"N": "11"}}, (
        f"SET n = n + :one on a Number attribute returned {resp['Attributes']!r}, expected n=11"
    )
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET history = list_append(history, :more)",
        ExpressionAttributeValues={":more": {"L": [{"S": "b"}]}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"history": {"L": [{"S": "a"}, {"S": "b"}]}}, (
        f"list_append(history, :more) on a List attribute returned {resp['Attributes']!r}, "
        f"expected [a, b]"
    )

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final["word"] == {"S": "hello"} and final["props"] == {"M": {"depth": {"N": "1"}}} \
        and final["tags"] == {"NS": ["1", "2"]}, (
        f"the three attributes under test must still read their original values: {final!r}"
    )
    assert final["n"] == {"N": "11"} and final["history"] == {"L": [{"S": "a"}, {"S": "b"}]}, (
        f"both positive controls must have landed: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
