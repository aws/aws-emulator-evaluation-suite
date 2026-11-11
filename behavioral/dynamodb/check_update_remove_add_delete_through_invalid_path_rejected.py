"""update-remove-add-delete-through-invalid-path-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-remove-add-delete-through-invalid-path-rejected"
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
    """REMOVE, ADD and DELETE each reject a nested path whose parent is not a container,
    leaving the item unchanged, while the same action against a real map or set succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {
        **key,
        "word": {"S": "scalar"},
        "counters": {"M": {"hits": {"N": "1"}}},
        "flags": {"M": {"labels": {"SS": ["a", "b"]}}},
    }
    ddb.put_item(TableName=table, Item=original)

    # REMOVE through a path whose parent ("word") is a String, not a map.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE word.child",
    ))
    assert code == "ValidationException", (
        f"REMOVE word.child with word stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"REMOVE word.child refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    # ADD through the same wrong-shape parent.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD word.hits :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"ADD word.hits :one with word stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"ADD word.hits :one refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    # DELETE through the same wrong-shape parent.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE word.tags :v",
        ExpressionAttributeValues={":v": {"SS": ["x"]}},
    ))
    assert code == "ValidationException", (
        f"DELETE word.tags :v with word stored as S answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"DELETE word.tags :v refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the three refused invalid-path updates the item is {unchanged!r}, expected it "
        f"unchanged from {original!r}"
    )

    # Positive controls: the identical action against a real container at the same depth.
    ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE counters.hits")
    after_remove = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "hits" not in after_remove["counters"]["M"], (
        f"REMOVE counters.hits on a real map left {after_remove['counters']!r}"
    )

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD counters.visits :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    )
    after_add = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_add["counters"]["M"]["visits"] == {"N": "1"}, (
        f"ADD counters.visits :one on a real map produced {after_add['counters']!r}, expected "
        f"visits=1"
    )

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE flags.labels :v",
        ExpressionAttributeValues={":v": {"SS": ["a"]}},
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(final["flags"]["M"]["labels"]["SS"]) == {"b"}, (
        f"DELETE flags.labels :v on a real set produced {final['flags']!r}, expected only 'b' left"
    )
    assert final["word"] == {"S": "scalar"}, (
        f"the attribute under test must still read its original value: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
