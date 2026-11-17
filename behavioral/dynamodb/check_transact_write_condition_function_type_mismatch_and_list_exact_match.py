"""transact-write-condition-function-type-mismatch-and-list-exact-match."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-condition-function-type-mismatch-and-list-exact-match"
GROUP = "transactions"
SERVICES = ["dynamodb"]
_CANCELED_ONE_FAILS = (
    "TransactionCanceledException",
    "Transaction cancelled, please refer cancellation reasons for specific reasons "
    "[ConditionalCheckFailed, None]",
)


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; RAISES if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _exists(ddb, table, pk):
    return "Item" in ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems ConditionCheck's begins_with against a Number attribute, and contains
    against a List for a value that is only a substring of one element, both evaluate false
    (cancelling the transaction with ConditionalCheckFailed) rather than raising a validation error.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-twicf-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "number-item"}, "v": {"N": "5"}, "sv": {"S": "hello"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "list-item"}, "tags": {"L": [{"S": "hello"}, {"S": "world"}]}})

    def _guarded_transaction(expr, value, marker):
        return ddb.transact_write_items(TransactItems=[
            {"ConditionCheck": {
                "TableName": t,
                "Key": {"pk": {"S": expr[0]}},
                "ConditionExpression": expr[1],
                "ExpressionAttributeValues": {":p": value},
            }},
            {"Put": {"TableName": t, "Item": {"pk": {"S": marker}, "x": {"S": "y"}}}},
        ])

    # begins_with against the N attribute "v": a type mismatch evaluates false, cancelling the
    # transaction with ConditionalCheckFailed rather than ValidationException.
    code, message = _error(
        lambda: _guarded_transaction(("number-item", "begins_with(v, :p)"), {"S": "5"}, "marker-n-mismatch")
    )
    assert (code, message) == _CANCELED_ONE_FAILS, (
        f"begins_with on an N attribute answered ({code!r}, {message!r}), expected {_CANCELED_ONE_FAILS!r}"
    )
    assert not _exists(ddb, t, "marker-n-mismatch"), (
        "the cancelled transaction must not have written its companion Put"
    )

    # Positive control: begins_with against the correctly typed S attribute "sv" still gates and
    # commits the companion Put, proving the mismatch above is about the type, not the function.
    _guarded_transaction(("number-item", "begins_with(sv, :p)"), {"S": "he"}, "marker-n-control")
    assert _exists(ddb, t, "marker-n-control"), (
        "begins_with on a correctly typed S attribute that holds must commit the companion Put"
    )

    # contains against the List "tags": a value that is only a substring of one element ("ell" of
    # "hello") is not an element of the list, so the condition evaluates false and cancels.
    code, message = _error(
        lambda: _guarded_transaction(("list-item", "contains(tags, :p)"), {"S": "ell"}, "marker-l-substring")
    )
    assert (code, message) == _CANCELED_ONE_FAILS, (
        f"contains on a List with a substring-only value answered ({code!r}, {message!r}), "
        f"expected {_CANCELED_ONE_FAILS!r}"
    )
    assert not _exists(ddb, t, "marker-l-substring"), (
        "the cancelled transaction must not have written its companion Put"
    )

    # Positive control: contains against the exact element "hello" commits the companion Put,
    # proving the list match requires an exact element, not a substring.
    _guarded_transaction(("list-item", "contains(tags, :p)"), {"S": "hello"}, "marker-l-control")
    assert _exists(ddb, t, "marker-l-control"), (
        "contains on a List matching an exact element must commit the companion Put"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
