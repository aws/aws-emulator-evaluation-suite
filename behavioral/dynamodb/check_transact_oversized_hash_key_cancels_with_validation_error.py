"""transact-oversized-hash-key-cancels-with-validation-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-oversized-hash-key-cancels-with-validation-error"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_HASH_MAX = 2048
_CANCEL_ONE_MSG = "Transaction cancelled, please refer cancellation reasons for specific reasons [ValidationError]"
_CANCEL_SECOND_MSG = (
    "Transaction cancelled, please refer cancellation reasons for specific reasons [None, ValidationError]"
)
_REASON_MSG = (
    "One or more parameter values were invalid: Size of hashkey has exceeded the maximum size "
    "limit of2048 bytes"
)


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message, CancellationReasons) of the ClientError fn() raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 2049-byte hash key in a TransactWriteItems Put, Delete, Update or ConditionCheck, or a
    TransactGetItems Get, cancels the transaction with a ValidationError reason; nothing is written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-txkeysize-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    # Positive control: an at-limit key commits through a transaction.
    limit_item = {"pk": {"S": "a" * _HASH_MAX}, "v": {"S": "at-limit"}}
    ddb.transact_write_items(TransactItems=[{"Put": {"TableName": table, "Item": limit_item}}])
    got = ddb.get_item(TableName=table, Key={"pk": limit_item["pk"]}, ConsistentRead=True).get("Item")
    assert got == limit_item, f"the at-limit transactional Put stored {got!r}"

    big = {"pk": {"S": "a" * (_HASH_MAX + 1)}}
    one_reason = [{"Code": "ValidationError", "Message": _REASON_MSG}]
    arms = [
        ("TransactWriteItems Put", ddb.transact_write_items, [
            {"Put": {"TableName": table, "Item": {**big, "v": {"S": "x"}}}}]),
        ("TransactWriteItems Delete", ddb.transact_write_items, [
            {"Delete": {"TableName": table, "Key": big}}]),
        ("TransactWriteItems Update", ddb.transact_write_items, [
            {"Update": {"TableName": table, "Key": big, "UpdateExpression": "SET v = :v",
                        "ExpressionAttributeValues": {":v": {"S": "x"}}}}]),
        ("TransactWriteItems ConditionCheck", ddb.transact_write_items, [
            {"ConditionCheck": {"TableName": table, "Key": big,
                                "ConditionExpression": "attribute_not_exists(pk)"}}]),
        ("TransactGetItems Get", ddb.transact_get_items, [
            {"Get": {"TableName": table, "Key": big}}]),
    ]
    for label, op, items in arms:
        code, msg, reasons = _error(lambda op=op, items=items: op(TransactItems=items))
        assert (code, msg) == ("TransactionCanceledException", _CANCEL_ONE_MSG), (
            f"{label} with a 2049-byte hash key gave {code!r}: {msg!r}"
        )
        assert reasons == one_reason, f"{label} cancellation reasons were {reasons!r}"

    # A valid sibling Put is not committed when the second action's key is over-size.
    sibling = {"pk": {"S": "sibling"}, "v": {"S": "x"}}
    code, msg, reasons = _error(lambda: ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": sibling}},
        {"Put": {"TableName": table, "Item": {**big, "v": {"S": "x"}}}},
    ]))
    assert (code, msg) == ("TransactionCanceledException", _CANCEL_SECOND_MSG), (
        f"a transaction whose second Put has a 2049-byte hash key gave {code!r}: {msg!r}"
    )
    want = [{"Code": "None"}, {"Code": "ValidationError", "Message": _REASON_MSG}]
    assert reasons == want, f"cancellation reasons were {reasons!r}, expected {want!r}"
    absent = ddb.get_item(TableName=table, Key={"pk": sibling["pk"]}, ConsistentRead=True).get("Item")
    assert absent is None, f"the cancelled transaction still wrote its valid Put: {absent!r}"
    count = ddb.scan(TableName=table, Select="COUNT", ConsistentRead=True)["Count"]
    assert count == 1, f"the table holds {count!r} items after the cancelled transactions, expected 1"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
