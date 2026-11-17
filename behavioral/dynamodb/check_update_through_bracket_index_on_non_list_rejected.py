"""update-through-bracket-index-on-non-list-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-through-bracket-index-on-non-list-rejected"
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


_PATH_INVALID = "The document path provided in the update expression is invalid for update"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A `[n]` bracket index in an update path is rejected with ValidationException when the
    attribute it indexes is a String or a Map rather than a List, leaving the item unchanged,
    while the identical bracket form against a real List element succeeds."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {
        **key,
        "word": {"S": "scalar"},
        "doc_map": {"M": {"x": {"N": "1"}}},
    }
    ddb.put_item(TableName=table, Item=original)

    # REMOVE/ADD/DELETE indexing a String attribute with [n].
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE word[0]",
    ))
    assert code == "ValidationException", (
        f"REMOVE word[0] with word stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"REMOVE word[0] refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD word[0] :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"ADD word[0] :one with word stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"ADD word[0] :one refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE word[0] :v",
        ExpressionAttributeValues={":v": {"SS": ["x"]}},
    ))
    assert code == "ValidationException", (
        f"DELETE word[0] :v with word stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"DELETE word[0] :v refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    # SET/REMOVE/ADD/DELETE indexing a Map attribute with [n].
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET doc_map[1] = :v",
        ExpressionAttributeValues={":v": {"S": "x"}},
    ))
    assert code == "ValidationException", (
        f"SET doc_map[1] with doc_map stored as M answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"SET doc_map[1] refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE doc_map[1]",
    ))
    assert code == "ValidationException", (
        f"REMOVE doc_map[1] with doc_map stored as M answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"REMOVE doc_map[1] refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD doc_map[1] :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"ADD doc_map[1] :one with doc_map stored as M answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"ADD doc_map[1] :one refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE doc_map[1] :v",
        ExpressionAttributeValues={":v": {"SS": ["x"]}},
    ))
    assert code == "ValidationException", (
        f"DELETE doc_map[1] :v with doc_map stored as M answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"DELETE doc_map[1] :v refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the seven refused bracket-index updates the item is {unchanged!r}, expected it "
        f"unchanged from {original!r}"
    )

    # Positive controls: the identical bracket forms against a real List at the same depth.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET lst = :l",
        ExpressionAttributeValues={":l": {"L": [{"SS": ["a", "b"]}, {"N": "5"}, {"S": "c"}]}},
    )

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET lst[2] = :v",
        ExpressionAttributeValues={":v": {"S": "z"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"lst": {"L": [{"S": "z"}]}}, (
        f"SET lst[2] on a real list returned {resp['Attributes']!r}, expected lst[2]='z'"
    )

    ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE lst[2]")
    after_remove = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_remove["lst"]["L"] == [{"SS": ["a", "b"]}, {"N": "5"}], (
        f"REMOVE lst[2] on a real list left {after_remove['lst']!r}"
    )

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD lst[1] :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"lst": {"L": [{"N": "6"}]}}, (
        f"ADD lst[1] :one on a real list returned {resp['Attributes']!r}, expected lst[1]=6"
    )

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE lst[0] :v",
        ExpressionAttributeValues={":v": {"SS": ["a"]}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"lst": {"L": [{"SS": ["b"]}]}}, (
        f"DELETE lst[0] :v on a real list returned {resp['Attributes']!r}, expected lst[0]={{'b'}}"
    )

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final["lst"]["L"] == [{"SS": ["b"]}, {"N": "6"}], (
        f"final list is {final['lst']!r}, expected [{{'b'}}, 6]"
    )
    assert final["word"] == {"S": "scalar"} and final["doc_map"] == {"M": {"x": {"N": "1"}}}, (
        f"the attributes under test must still read their original values: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
