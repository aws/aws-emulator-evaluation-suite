"""transact-get-and-write-items-table-arn-naming-another-region-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-get-and-write-items-table-arn-naming-another-region-rejected"
GROUP = "transactions"
SERVICES = ["dynamodb"]


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


def _other_region(ctx) -> str:
    """The scenario's second region: us-east-1, unless the check already runs there."""
    return "us-east-1" if ctx.region != "us-east-1" else "us-west-2"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactGetItems and TransactWriteItems refuse a TableName ARN naming a different Region with
    a ValidationException on that member's tableName path, and write nothing; the same ARN
    addressed from its own Region reads and writes normally.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    other = _other_region(ctx)
    here = ctx.client("dynamodb")
    # region-pinned: the table ARN under test must name a Region other than the caller's.
    there = ctx.client("dynamodb", region=other)
    table = ctx.unique_name("sim2real-behav-txnarn-")
    there.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: there.delete_table(TableName=table))
    there.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    arn = there.describe_table(TableName=table)["Table"]["TableArn"]
    assert arn.split(":")[3] == other, f"the {other} table's ARN is {arn!r}"

    seed_key = {"pk": {"S": "row-seed"}}
    there.put_item(TableName=table, Item={**seed_key, "v": {"S": "seed"}})

    _GET_WRONG_REGION = (
        "ValidationException",
        f"1 validation error detected: Value '{arn}' at "
        "'transactItems.1.member.get.tableName' failed to satisfy constraint: Invalid AWS region",
    )
    expect_error(
        lambda: here.transact_get_items(TransactItems=[{"Get": {"TableName": arn, "Key": seed_key}}]),
        *_GET_WRONG_REGION,
    )

    new_key = {"pk": {"S": "row-new"}}
    _PUT_WRONG_REGION = (
        "ValidationException",
        f"1 validation error detected: Value '{arn}' at "
        "'transactItems.1.member.put.tableName' failed to satisfy constraint: Invalid AWS region",
    )
    expect_error(
        lambda: here.transact_write_items(
            TransactItems=[{"Put": {"TableName": arn, "Item": {**new_key, "v": {"S": "never"}}}}]
        ),
        *_PUT_WRONG_REGION,
    )
    never_written = there.get_item(TableName=table, Key=new_key, ConsistentRead=True)
    assert "Item" not in never_written, (
        f"the cross-Region refusal must not create the item, got {never_written.get('Item')!r}"
    )

    # Positive control: the same ARN, addressed from its own Region, reads and writes normally.
    there.transact_write_items(
        TransactItems=[{"Put": {"TableName": arn, "Item": {**new_key, "v": {"S": "ok"}}}}]
    )
    written = there.get_item(TableName=table, Key=new_key, ConsistentRead=True)["Item"]
    assert written["v"] == {"S": "ok"}, written

    got = there.transact_get_items(TransactItems=[{"Get": {"TableName": arn, "Key": seed_key}}])
    assert got["Responses"][0]["Item"]["v"] == {"S": "seed"}, got


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
