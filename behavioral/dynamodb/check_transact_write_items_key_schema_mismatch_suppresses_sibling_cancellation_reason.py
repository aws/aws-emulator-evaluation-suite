"""transact-write-items-key-schema-mismatch-suppresses-sibling-cancellation-reason."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-key-schema-mismatch-suppresses-sibling-cancellation-reason"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_KEY_SCHEMA = "The provided key element does not match the schema"
_CONDITION_FAILED = "The conditional request failed"
_UPDATE_TYPE_ERROR = "An operand in the update expression has an incorrect data type"


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo() -> None:
        deadline = time.monotonic() + 300.0
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
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table!r} not ACTIVE before the deadline, last status {status!r}")


def _cancelled(fn):
    """(Error.Code, Error.Message, CancellationReasons) of the TransactionCanceledException fn() raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the transaction to be cancelled, but it succeeded: {result!r}")


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key-schema ValidationError in one TransactWriteItems slot reports every sibling slot's
    cancellation reason as Code='None' regardless of order, even a sibling that would itself have
    failed its own ConditionCheck or update; nothing is written in any case.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-txsupp-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    typed_key = {"pk": {"S": "typed"}}
    typed_item = {**typed_key, "v": {"S": "not-a-number"}}
    ddb.put_item(TableName=table, Item=typed_item)
    missing_key = {"pk": {"S": "absent-target"}}
    wrong_key = {"pk": {"N": "1"}}

    cond_check_fail = {"ConditionCheck": {
        "TableName": table, "Key": missing_key, "ConditionExpression": "attribute_exists(pk)",
    }}
    type_error_update = {"Update": {
        "TableName": table, "Key": typed_key, "UpdateExpression": "ADD v :inc",
        "ExpressionAttributeValues": {":inc": {"N": "1"}},
    }}
    wrong_key_delete = {"Delete": {"TableName": table, "Key": wrong_key}}

    # Baseline: without any key-schema defect, a failing ConditionCheck carries its OWN reason.
    code, _msg, reasons = _cancelled(lambda: ddb.transact_write_items(TransactItems=[
        cond_check_fail,
        {"Put": {"TableName": table, "Item": {"pk": {"S": "baseline-put"}}}},
    ]))
    assert code == "TransactionCanceledException", f"baseline: expected TransactionCanceledException, got {code!r}"
    assert reasons[0] == {"Code": "ConditionalCheckFailed", "Message": _CONDITION_FAILED}, (
        f"baseline: the failing ConditionCheck's own reason must carry through, got {reasons[0]!r}"
    )
    assert reasons[1] == {"Code": "None"}, f"baseline: the passing Put's slot must carry Code='None', got {reasons[1]!r}"

    # Baseline: without any key-schema defect, a runtime update type error carries its OWN reason.
    code, _msg, reasons = _cancelled(lambda: ddb.transact_write_items(TransactItems=[
        type_error_update,
        {"Put": {"TableName": table, "Item": {"pk": {"S": "baseline-put-2"}}}},
    ]))
    assert code == "TransactionCanceledException", f"baseline: expected TransactionCanceledException, got {code!r}"
    assert reasons[0] == {"Code": "ValidationError", "Message": _UPDATE_TYPE_ERROR}, (
        f"baseline: ADD on a non-numeric attribute must cancel with its own reason, got {reasons[0]!r}"
    )
    assert reasons[1] == {"Code": "None"}, f"baseline: the passing Put's slot must carry Code='None', got {reasons[1]!r}"

    # 1. A LATER key-schema mismatch suppresses an EARLIER failing ConditionCheck into Code='None'.
    code, _msg, reasons = _cancelled(lambda: ddb.transact_write_items(
        TransactItems=[cond_check_fail, wrong_key_delete]))
    assert code == "TransactionCanceledException", f"case 1: expected TransactionCanceledException, got {code!r}"
    assert reasons[0] == {"Code": "None"}, (
        f"case 1: the key-schema mismatch must suppress the earlier failing ConditionCheck to 'None', got {reasons[0]!r}"
    )
    assert reasons[1] == {"Code": "ValidationError", "Message": _KEY_SCHEMA}, (
        f"case 1: the mismatched slot must carry the exact schema-mismatch reason, got {reasons[1]!r}"
    )

    # 2. A key-schema mismatch FIRST suppresses a LATER failing ConditionCheck the same way.
    code, _msg, reasons = _cancelled(lambda: ddb.transact_write_items(
        TransactItems=[wrong_key_delete, cond_check_fail]))
    assert code == "TransactionCanceledException", f"case 2: expected TransactionCanceledException, got {code!r}"
    assert reasons[0] == {"Code": "ValidationError", "Message": _KEY_SCHEMA}, (
        f"case 2: the mismatched slot must carry the exact schema-mismatch reason, got {reasons[0]!r}"
    )
    assert reasons[1] == {"Code": "None"}, (
        f"case 2: the key-schema mismatch must suppress the later failing ConditionCheck to 'None', got {reasons[1]!r}"
    )

    # 3. A key-schema mismatch suppresses an EARLIER runtime update type error into Code='None' too.
    code, _msg, reasons = _cancelled(lambda: ddb.transact_write_items(
        TransactItems=[type_error_update, wrong_key_delete]))
    assert code == "TransactionCanceledException", f"case 3: expected TransactionCanceledException, got {code!r}"
    assert reasons[0] == {"Code": "None"}, (
        f"case 3: the key-schema mismatch must suppress the earlier update type error to 'None', got {reasons[0]!r}"
    )
    assert reasons[1] == {"Code": "ValidationError", "Message": _KEY_SCHEMA}, (
        f"case 3: the mismatched slot must carry the exact schema-mismatch reason, got {reasons[1]!r}"
    )

    # Nothing from any of the five cancelled transactions above was ever written.
    got = _get(ddb, table, typed_key)
    assert got == typed_item, f"a cancelled transaction changed the typed item to {got!r}"
    assert _get(ddb, table, missing_key) is None, "a cancelled transaction created the missing-target item"
    names = {i["pk"]["S"] for i in ddb.scan(TableName=table, ConsistentRead=True)["Items"]}
    assert names == {"typed"}, f"the table holds {sorted(names)!r} after only cancelled transactions, expected only 'typed'"

    # Positive control: a well-formed transaction against the same table still commits.
    ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": {"pk": {"S": "control"}}}},
    ])
    assert _get(ddb, table, {"pk": {"S": "control"}}) == {"pk": {"S": "control"}}, (
        "a well-formed TransactWriteItems after the cancelled ones did not commit"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
