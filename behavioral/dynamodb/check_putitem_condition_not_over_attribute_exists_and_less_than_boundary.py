"""putitem-condition-not-over-attribute-exists-and-less-than-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-not-over-attribute-exists-and-less-than-boundary"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``. RAISES on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem admits a write under `NOT attribute_exists(#m)` while #m is absent, and under
    `NOT (#n < :seven)` while #n equals 7; each is refused once the negated operand turns true,
    leaving the stored item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-put-not-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def read(pk: str):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # --- NOT attribute_exists: holds while #m is absent, fails once #m is present.
    exists_key = "ddb-put-not-exists"
    seeded = {"pk": {"S": exists_key}, "tag": {"S": "seed"}}
    ddb.put_item(TableName=table, Item=seeded)

    holding = {"pk": {"S": exists_key}, "tag": {"S": "not-exists-holds"}}
    ddb.put_item(
        TableName=table, Item=holding,
        ConditionExpression="NOT attribute_exists(#m)",
        ExpressionAttributeNames={"#m": "m"},
    )
    got = read(exists_key)
    assert got == holding, f"PutItem under NOT attribute_exists(absent) left {got!r}, expected {holding!r}"

    # Make #m present, outside the tested condition, so the next attempt breaks exactly one thing.
    present = {"pk": {"S": exists_key}, "tag": {"S": "m-now-present"}, "m": {"S": "here"}}
    ddb.put_item(TableName=table, Item=present)

    rejected_write = {"pk": {"S": exists_key}, "tag": {"S": "not-exists-should-not-apply"}}
    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item=rejected_write,
            ConditionExpression="NOT attribute_exists(#m)",
            ExpressionAttributeNames={"#m": "m"},
        ),
        *_CCF,
    )
    got = read(exists_key)
    assert got == present, f"PutItem under a failing NOT attribute_exists(#m) left {got!r}, expected {present!r} unchanged"

    # --- NOT (#n < :seven): holds exactly at the boundary n == 7, fails once n < 7.
    lt_key = "ddb-put-not-lt-boundary"
    seven = {"pk": {"S": lt_key}, "n": {"N": "7"}, "tag": {"S": "seed"}}
    ddb.put_item(TableName=table, Item=seven)

    holding_lt = {"pk": {"S": lt_key}, "n": {"N": "7"}, "tag": {"S": "not-lt-holds-at-boundary"}}
    ddb.put_item(
        TableName=table, Item=holding_lt,
        ConditionExpression="NOT (#n < :seven)",
        ExpressionAttributeNames={"#n": "n"},
        ExpressionAttributeValues={":seven": {"N": "7"}},
    )
    got = read(lt_key)
    assert got == holding_lt, f"PutItem under NOT (#n < 7) with n==7 left {got!r}, expected {holding_lt!r}"

    # Drop below the boundary, outside the tested condition.
    six = {"pk": {"S": lt_key}, "n": {"N": "6"}, "tag": {"S": "n-now-below-boundary"}}
    ddb.put_item(TableName=table, Item=six)

    rejected_lt = {"pk": {"S": lt_key}, "n": {"N": "6"}, "tag": {"S": "not-lt-should-not-apply"}}
    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item=rejected_lt,
            ConditionExpression="NOT (#n < :seven)",
            ExpressionAttributeNames={"#n": "n"},
            ExpressionAttributeValues={":seven": {"N": "7"}},
        ),
        *_CCF,
    )
    got = read(lt_key)
    assert got == six, f"PutItem under a failing NOT (#n < 7) with n==6 left {got!r}, expected {six!r} unchanged"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
