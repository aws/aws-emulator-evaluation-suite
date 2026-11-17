"""update-item-add-delete-on-map-attribute-and-nested-arithmetic-type-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-delete-on-map-attribute-and-nested-arithmetic-type-mismatch-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0

_TYPE_MISMATCH = "An operand in the update expression has an incorrect data type"


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
    """ADD and DELETE on a Map-typed attribute, and SET arithmetic on a nested leaf of the
    wrong type, are each rejected with ValidationException and leave the item unchanged; the
    same actions against same-typed siblings still apply.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {
        **key,
        "cfg": {"M": {"region": {"S": "us-west-2"}}},
        "hits": {"N": "10"},
        "labels": {"SS": ["a", "b"]},
        "nested": {"M": {"stat": {"M": {"score": {"S": "not-a-number"}, "visits": {"N": "1"}}}}},
    }
    ddb.put_item(TableName=table, Item=original)

    cfg_names = {"#a": "cfg"}
    score_names = {"#n": "nested", "#t": "stat", "#s": "score"}
    visits_names = {"#n": "nested", "#t": "stat", "#v": "visits"}

    # ADD onto a Map-typed top-level attribute: ADD only accepts Number or Set operands.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #a :one",
        ExpressionAttributeNames=cfg_names, ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"ADD cfg :one with cfg stored as M answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _TYPE_MISMATCH, (
        f"ADD cfg :one refusal message is {message!r}, expected {_TYPE_MISMATCH!r}"
    )

    # DELETE onto a Map-typed top-level attribute: DELETE only accepts Set operands against a Set.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE #a :v",
        ExpressionAttributeNames=cfg_names, ExpressionAttributeValues={":v": {"SS": ["x"]}},
    ))
    assert code == "ValidationException", (
        f"DELETE cfg :v with cfg stored as M answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _TYPE_MISMATCH, (
        f"DELETE cfg :v refusal message is {message!r}, expected {_TYPE_MISMATCH!r}"
    )

    # SET arithmetic on a nested leaf (nested.stat.score) stored as a String.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET #n.#t.#s = #n.#t.#s + :one",
        ExpressionAttributeNames=score_names, ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"SET nested.stat.score = nested.stat.score + :one with score stored as S answered "
        f"{code!r} ({message!r}), expected ValidationException"
    )
    assert message == _TYPE_MISMATCH, (
        f"nested arithmetic refusal message is {message!r}, expected {_TYPE_MISMATCH!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the three refused type-mismatched updates the item is {unchanged!r}, expected it "
        f"unchanged from {original!r}"
    )

    # Positive controls: the identical action against a same-typed sibling applies.
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD hits :delta",
        ExpressionAttributeValues={":delta": {"N": "5"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"hits": {"N": "15"}}, (
        f"ADD hits :delta on a Number attribute returned {resp['Attributes']!r}, expected hits=15"
    )

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE labels :v",
        ExpressionAttributeValues={":v": {"SS": ["a"]}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"labels": {"SS": ["b"]}}, (
        f"DELETE labels :v on a String Set attribute returned {resp['Attributes']!r}, expected labels={{b}}"
    )

    resp = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET #n.#t.#v = #n.#t.#v + :one",
        ExpressionAttributeNames=visits_names, ExpressionAttributeValues={":one": {"N": "1"}},
        ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"nested": {"M": {"stat": {"M": {"visits": {"N": "2"}}}}}}, (
        f"nested SET arithmetic on a Number leaf returned {resp['Attributes']!r}, expected visits=2"
    )

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final["cfg"] == {"M": {"region": {"S": "us-west-2"}}}, (
        f"cfg must still read its original value: {final['cfg']!r}"
    )
    assert final["nested"]["M"]["stat"]["M"]["score"] == {"S": "not-a-number"}, (
        f"nested.stat.score must still read its original value: {final['nested']!r}"
    )
    assert final["hits"] == {"N": "15"} and set(final["labels"]["SS"]) == {"b"} \
        and final["nested"]["M"]["stat"]["M"]["visits"] == {"N": "2"}, (
        f"all three positive controls must have landed: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
