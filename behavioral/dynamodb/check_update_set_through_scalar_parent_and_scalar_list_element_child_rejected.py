"""update-set-through-scalar-parent-and-scalar-list-element-child-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-set-through-scalar-parent-and-scalar-list-element-child-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0

_PATH_INVALID = "The document path provided in the update expression is invalid for update"


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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """SET rejects a path through a scalar attribute and through a scalar list element, leaving
    the item unchanged, while the same SET form against a real map or a map-valued element succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {
        **key,
        "word": {"S": "scalar"},
        "tags": {"L": [{"S": "a"}, {"S": "b"}]},
        "box": {"M": {}},
        "entries": {"L": [{"M": {}}]},
    }
    ddb.put_item(TableName=table, Item=original)

    # SET through a scalar top-level parent ("word" is a String, not a map).
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET word.child = :v",
        ExpressionAttributeValues={":v": {"S": "x"}},
    ))
    assert code == "ValidationException", (
        f"SET word.child with word stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"SET word.child refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    # SET through a scalar list element ("tags[0]" is a String, not a map).
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET tags[0].child = :v",
        ExpressionAttributeValues={":v": {"S": "x"}},
    ))
    assert code == "ValidationException", (
        f"SET tags[0].child with tags[0] stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"SET tags[0].child refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the two refused SETs the item is {unchanged!r}, expected it unchanged from "
        f"{original!r}"
    )

    # Positive controls: the identical SET forms against a real map and a map-valued list element.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET box.child = :v",
        ExpressionAttributeValues={":v": {"S": "x"}},
    )
    after_box = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_box["box"] == {"M": {"child": {"S": "x"}}}, (
        f"SET box.child on a real map produced {after_box['box']!r}, expected child='x'"
    )

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET entries[0].child = :v",
        ExpressionAttributeValues={":v": {"S": "x"}},
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final["entries"] == {"L": [{"M": {"child": {"S": "x"}}}]}, (
        f"SET entries[0].child on a map-valued list element produced {final['entries']!r}, "
        f"expected child='x'"
    )
    assert final["word"] == {"S": "scalar"} and final["tags"] == original["tags"], (
        f"the attributes under test must still read their original values: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
