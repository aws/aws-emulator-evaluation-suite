"""transact-write-items-put-condition-value-nesting-depth-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-put-condition-value-nesting-depth-rejected"
GROUP = "limits"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_NESTING_MESSAGE = (
    "Nesting Levels have exceeded supported limits: Attributes in the item have nested levels "
    "beyond supported limit"
)


def _deep(levels: int) -> dict:
    """A chain of `levels` nested maps around one scalar leaf, `levels` + 1 deep in total."""
    value = {"S": "leaf"}
    for _ in range(levels):
        value = {"M": {"n": value}}
    return value


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A 33-level value in a TransactWriteItems Put action's own ConditionExpression is a
    top-level ValidationException for the whole call; a 32-level one is accepted, and the
    refused call's sibling Update action never takes effect either.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbtxnput-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    def get(pk):
        return ddb.get_item(TableName=t, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # Positive control: a 32-level condition value on a Put action inside TransactWriteItems is
    # within the limit and the item lands.
    at_limit = _deep(31)
    ddb.transact_write_items(TransactItems=[
        {"Put": {
            "TableName": t, "Item": {"pk": {"S": "at-limit"}, "v": {"S": "ok"}},
            "ConditionExpression": "attribute_not_exists(pk) OR :d = :d",
            "ExpressionAttributeValues": {":d": at_limit},
        }},
    ])
    ctl = get("at-limit")
    assert ctl == {"pk": {"S": "at-limit"}, "v": {"S": "ok"}}, (
        f"a 32-level Put condition value inside TransactWriteItems must be accepted, stored {ctl!r}"
    )

    # Seed the sibling item the negative case's Update action targets.
    ddb.put_item(TableName=t, Item={"pk": {"S": "sibling"}, "ctr": {"N": "1"}})

    over_limit = _deep(32)
    code, message = _error(lambda: ddb.transact_write_items(TransactItems=[
        {"Put": {
            "TableName": t, "Item": {"pk": {"S": "deep-put-target"}, "v": {"S": "new"}},
            "ConditionExpression": "attribute_not_exists(pk) OR :d = :d",
            "ExpressionAttributeValues": {":d": over_limit},
        }},
        {"Update": {
            "TableName": t, "Key": {"pk": {"S": "sibling"}},
            "UpdateExpression": "SET ctr = :two",
            "ExpressionAttributeValues": {":two": {"N": "2"}},
        }},
    ]))
    assert code == ERR_VALIDATION, (
        f"a 33-level Put condition value inside TransactWriteItems must be {ERR_VALIDATION} for "
        f"the whole call, got {code!r}: {message!r}"
    )
    assert message == _NESTING_MESSAGE, (
        f"expected the exact ValidationException message, got {message!r}"
    )
    deep_put = get("deep-put-target")
    assert deep_put is None, f"the refused Put must not be written, got {deep_put!r}"
    sibling = get("sibling")
    assert sibling == {"pk": {"S": "sibling"}, "ctr": {"N": "1"}}, (
        f"the transaction's own valid Update action must not take effect either, got {sibling!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
