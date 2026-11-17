"""scan-filter-size-function-name-is-case-sensitive."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-size-function-name-is-case-sensitive"
GROUP = "scan"
SERVICES = ["dynamodb"]

_TITLE_CASE_REJECTED = ("ValidationException", "Invalid FilterExpression: Invalid function name; function: Size")
_UPPER_CASE_REJECTED = ("ValidationException", "Invalid FilterExpression: Invalid function name; function: SIZE")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression rejects size() under any other case as an unknown function name,
    naming the exact spelling it was given, while the correctly-cased call still matches.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbcase-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={"pk": {"S": "a"}, "s": {"S": "abc"}})

    expect_error(
        lambda: ddb.scan(TableName=table, ConsistentRead=True,
                         FilterExpression="Size(s) = :n", ExpressionAttributeValues={":n": {"N": "3"}}),
        *_TITLE_CASE_REJECTED,
    )
    expect_error(
        lambda: ddb.scan(TableName=table, ConsistentRead=True,
                         FilterExpression="SIZE(s) = :n", ExpressionAttributeValues={":n": {"N": "3"}}),
        *_UPPER_CASE_REJECTED,
    )

    # Positive control: the correctly-cased call matches the seeded item.
    ok = ddb.scan(TableName=table, ConsistentRead=True,
                 FilterExpression="size(s) = :n", ExpressionAttributeValues={":n": {"N": "3"}})
    assert {i["pk"]["S"] for i in ok["Items"]} == {"a"}, (
        f"size(s) = 3 selected {sorted(i['pk']['S'] for i in ok['Items'])!r}, expected ['a']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
