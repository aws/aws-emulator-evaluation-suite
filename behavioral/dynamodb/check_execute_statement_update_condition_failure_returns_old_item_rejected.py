"""execute-statement-update-condition-failure-returns-old-item-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-update-condition-failure-returns-old-item-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]
ERR_CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailedException"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL ExecuteStatement UPDATE ... WHERE whose condition does not match raises
    ConditionalCheckFailedException with the exact message, and with
    ReturnValuesOnConditionCheckFailure=ALL_OLD the exception carries the item's current value.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "cond"}}
    ddb.put_item(TableName=t, Item={"pk": {"S": "cond"}, "val": {"S": "original"}})

    # Positive control: an ExecuteStatement UPDATE whose WHERE condition matches the current
    # value succeeds.
    ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
        Parameters=[{"S": "control"}, {"S": "cond"}, {"S": "original"}],
    )
    controlled = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)["Item"]
    assert controlled.get("val") == {"S": "control"}, (
        f"positive control update did not take effect, got {controlled}"
    )

    # Break exactly one thing: the WHERE condition checks the now-STALE value 'original'; the
    # current value is 'control'.
    try:
        ddb.execute_statement(
            Statement=f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            Parameters=[{"S": "clobbered"}, {"S": "cond"}, {"S": "original"}],
            ReturnValuesOnConditionCheckFailure="ALL_OLD",
        )
        err = None
    except ClientError as exc:
        err = exc.response
    assert err is not None, "an ExecuteStatement UPDATE with a stale WHERE condition must be rejected"
    assert err["Error"]["Code"] == ERR_CONDITIONAL_CHECK_FAILED, (
        f"expected {ERR_CONDITIONAL_CHECK_FAILED}, got {err['Error'].get('Code')!r}"
    )
    assert err["Error"]["Message"] == "The conditional request failed", (
        f"expected AWS's exact ConditionalCheckFailedException message, got {err['Error']['Message']!r}"
    )
    assert "Item" in err, (
        f"ReturnValuesOnConditionCheckFailure=ALL_OLD must surface the current item on rejection, got {err}"
    )
    assert err["Item"].get("val") == {"S": "control"}, (
        f"the surfaced item must carry the CURRENT value 'control', not the stale expectation, got {err['Item']}"
    )

    # Effect absent: an independent read (GetItem, not ExecuteStatement's own exception) shows
    # the rejected update did not touch the item.
    unchanged = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)["Item"]
    assert unchanged.get("val") == {"S": "control"}, (
        f"a rejected conditional UPDATE must not modify the item, got {unchanged}"
    )

    # Restore: the identical statement, with the condition matching the CURRENT value, now succeeds.
    ddb.execute_statement(
        Statement=f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
        Parameters=[{"S": "restored"}, {"S": "cond"}, {"S": "control"}],
        ReturnValuesOnConditionCheckFailure="ALL_OLD",
    )
    restored = ddb.get_item(TableName=t, Key=key, ConsistentRead=True)["Item"]
    assert restored.get("val") == {"S": "restored"}, (
        f"an ExecuteStatement UPDATE whose condition matches the current value must succeed, got {restored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
