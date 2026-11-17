"""update-remove-through-missing-nested-parent-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-remove-through-missing-nested-parent-rejected"
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
    """REMOVE rejects a nested path whose parent attribute is entirely absent from the item,
    leaving the item unchanged, while the same REMOVE form against a real map succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {
        **key,
        "keep": {"S": "k"},
        "box": {"M": {"hits": {"N": "1"}}},
    }
    ddb.put_item(TableName=table, Item=original)

    # REMOVE through a nested path whose parent ("absent") does not exist on the item at all.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE absent.child",
    ))
    assert code == "ValidationException", (
        f"REMOVE absent.child with no 'absent' attribute answered {code!r} ({message!r}), "
        f"expected ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"REMOVE absent.child refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the refused REMOVE the item is {unchanged!r}, expected it unchanged from "
        f"{original!r}"
    )
    assert "absent" not in unchanged, (
        f"the refused REMOVE must not create the absent parent: {unchanged!r}"
    )

    # The same expression against a nonexistent item is a no-op, not a rejection: there is
    # nothing stored to validate the path against, and REMOVE never upserts.
    absent_key = {"pk": {"S": "nowhere"}}
    ddb.update_item(TableName=table, Key=absent_key, UpdateExpression="REMOVE absent.child")
    assert ddb.get_item(TableName=table, Key=absent_key, ConsistentRead=True).get("Item") is None, (
        "REMOVE absent.child against a nonexistent item must not create it"
    )

    # Positive control: the identical REMOVE form against a real map on the same item.
    ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE box.hits")
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "hits" not in final["box"]["M"], (
        f"REMOVE box.hits on a real map left {final['box']!r}"
    )
    assert final["keep"] == {"S": "k"}, (
        f"the attribute under test must still read its original value: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
