"""update-item-legacy-delete-and-arithmetic-set-on-hash-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-legacy-delete-and-arithmetic-set-on-hash-key-rejected"
GROUP = "item_crud"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """The Error dict of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this UpdateItem, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem rejects a legacy AttributeUpdates DELETE naming the hash key and a
    multi-clause UpdateExpression whose arithmetic SET clause targets the hash key.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-hkdel-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "hk-item"}}
    ddb.put_item(TableName=table, Item={
        **key,
        "note": {"S": "orig-note"},
        "tally": {"N": "1"},
        "m": {"M": {"b": {"N": "2"}}},
        "lst": {"L": [{"N": "10"}, {"N": "20"}]},
    })

    # Positive control: a multi-clause UpdateExpression with an arithmetic clause on
    # non-key attributes succeeds, so the rejections below are specific to touching pk.
    ddb.update_item(
        TableName=table,
        Key=key,
        UpdateExpression="SET note = :v1, tally = tally + :v2",
        ExpressionAttributeValues={":v1": {"S": "updated-note"}, ":v2": {"N": "4"}},
    )
    after_control = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_control["note"] == {"S": "updated-note"}, (
        f"positive control: expected note=updated-note, got {after_control.get('note')!r}"
    )
    assert after_control["tally"] == {"N": "5"}, (
        f"positive control: expected tally=5, got {after_control.get('tally')!r}"
    )

    err = _error(lambda: ddb.update_item(
        TableName=table,
        Key=key,
        AttributeUpdates={"pk": {"Action": "DELETE"}},
    ))
    assert err.get("Code") == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {err}"
    expected_key_msg = (
        "One or more parameter values were invalid: Cannot update attribute pk. "
        "This attribute is part of the key"
    )
    assert err.get("Message") == expected_key_msg, (
        f"expected message {expected_key_msg!r}, got {err.get('Message')!r}"
    )

    after_delete = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_delete == after_control, (
        f"the refused legacy DELETE on pk must leave the item unchanged, got {after_delete!r}"
    )

    err2 = _error(lambda: ddb.update_item(
        TableName=table,
        Key=key,
        UpdateExpression="SET note = :v3, pk = m.b + lst[1]",
        ExpressionAttributeValues={":v3": {"S": "should-not-apply"}},
    ))
    assert err2.get("Code") == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {err2}"
    assert err2.get("Message") == expected_key_msg, (
        f"expected message {expected_key_msg!r}, got {err2.get('Message')!r}"
    )

    after_arith = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_arith == after_control, (
        "the refused multi-clause arithmetic SET on pk must leave the item unchanged "
        f"(including the note clause in the same request), got {after_arith!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
