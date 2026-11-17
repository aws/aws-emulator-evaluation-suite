"""delete-item-conditional-check-failure-response-carries-no-consumed-capacity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-conditional-check-failure-response-carries-no-consumed-capacity"
GROUP = "capacity"
SERVICES = ["dynamodb"]

_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


def _error(fn):
    """(code, message, response) of the ClientError fn() raises; raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message, response = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"
    return response


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unconditional DeleteItem with ReturnConsumedCapacity=TOTAL reports the write units it
    used, while the ConditionalCheckFailedException answer to a DeleteItem whose ConditionExpression
    fails carries no ConsumedCapacity member and the item stays exactly as written.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-delccf-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- Positive control: an unconditional DeleteItem of a real item really deletes and bills.
    ddb.put_item(TableName=table, Item={"pk": {"S": "control"}, "v": {"S": "ctrl"}})
    control_cc = ddb.delete_item(
        TableName=table, Key={"pk": {"S": "control"}}, ReturnConsumedCapacity="TOTAL",
    )["ConsumedCapacity"]
    assert control_cc["CapacityUnits"] == 1.0, (
        f"an unconditional DeleteItem of a small item must bill 1.0 write capacity unit, got "
        f"{control_cc['CapacityUnits']!r}"
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "control"}}, ConsistentRead=True).get("Item") is None, (
        "the control item must be gone after its unconditional delete"
    )

    # --- A failing ConditionExpression rejects the delete and bills nothing.
    ddb.put_item(TableName=table, Item={"pk": {"S": "guarded"}, "v": {"S": "untouched"}})
    response = expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key={"pk": {"S": "guarded"}},
            ConditionExpression="attribute_not_exists(pk)", ReturnConsumedCapacity="TOTAL",
        ),
        *_CCFE,
    )
    assert "ConsumedCapacity" not in response, (
        f"a rejected conditional DeleteItem must carry no ConsumedCapacity member, got "
        f"{response.get('ConsumedCapacity')!r}"
    )
    still_there = ddb.get_item(TableName=table, Key={"pk": {"S": "guarded"}}, ConsistentRead=True).get("Item")
    assert still_there == {"pk": {"S": "guarded"}, "v": {"S": "untouched"}}, (
        f"the rejected conditional DeleteItem must leave the item exactly as written, got {still_there!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
