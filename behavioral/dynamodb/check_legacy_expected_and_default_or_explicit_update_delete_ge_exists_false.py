"""legacy-expected-and-default-or-explicit-update-delete-ge-exists-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-expected-and-default-or-explicit-update-delete-ge-exists-false"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


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


def _expected(threshold: str):
    """A two-condition legacy Expected: score GE threshold, and extra must not exist."""
    return {
        "score": {"ComparisonOperator": "GE", "AttributeValueList": [{"N": threshold}]},
        "extra": {"Exists": False},
    }


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Two legacy Expected conditions on UpdateItem/DeleteItem are ANDed when ConditionalOperator
    is omitted, and ORed under ConditionalOperator='OR': AND needs both GE and Exists:false true
    or raises ConditionalCheckFailedException; OR lands when either is true.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.ConditionalOperator.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-legcondupd-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def put(pk: str, score: str, extra_present: bool) -> None:
        item = {"pk": {"S": pk}, "score": {"N": score}}
        if extra_present:
            item["extra"] = {"S": "present"}
        ddb.put_item(TableName=table, Item=item)

    def get(pk: str):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # --- UpdateItem: default AND (ConditionalOperator omitted) ---
    put("u-and-pass", "50", extra_present=False)  # score GE 10 true, extra Exists:false true
    ddb.update_item(
        TableName=table, Key={"pk": {"S": "u-and-pass"}},
        AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
        Expected=_expected("10"),
    )
    got = get("u-and-pass")
    assert got is not None and got.get("marker") == {"S": "applied"}, (
        f"UpdateItem default-AND with both conditions true did not land: {got!r}"
    )

    put("u-and-fail", "50", extra_present=True)  # score GE 10 true, extra Exists:false FALSE
    expect_error(lambda: ddb.update_item(
        TableName=table, Key={"pk": {"S": "u-and-fail"}},
        AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
        Expected=_expected("10"),
    ), *_CCFE)
    got = get("u-and-fail")
    assert got is not None and "marker" not in got, (
        f"UpdateItem default-AND refusal must not have applied the update: {got!r}"
    )

    # --- UpdateItem: explicit OR ---
    put("u-or-pass", "5", extra_present=False)  # score GE 10 FALSE, extra Exists:false true
    ddb.update_item(
        TableName=table, Key={"pk": {"S": "u-or-pass"}},
        AttributeUpdates={"marker": {"Value": {"S": "applied"}, "Action": "PUT"}},
        Expected=_expected("10"), ConditionalOperator="OR",
    )
    got = get("u-or-pass")
    assert got is not None and got.get("marker") == {"S": "applied"}, (
        f"UpdateItem OR with exactly one condition true did not land: {got!r}"
    )

    # --- DeleteItem: default AND (ConditionalOperator omitted) ---
    put("d-and-pass", "50", extra_present=False)
    ddb.delete_item(TableName=table, Key={"pk": {"S": "d-and-pass"}}, Expected=_expected("10"))
    assert get("d-and-pass") is None, "DeleteItem default-AND with both conditions true left the item"

    put("d-and-fail", "50", extra_present=True)
    expect_error(lambda: ddb.delete_item(
        TableName=table, Key={"pk": {"S": "d-and-fail"}}, Expected=_expected("10"),
    ), *_CCFE)
    got = get("d-and-fail")
    assert got is not None and got.get("extra") == {"S": "present"}, (
        f"DeleteItem default-AND refusal must leave the item untouched: {got!r}"
    )

    # --- DeleteItem: explicit OR ---
    put("d-or-pass", "5", extra_present=False)
    ddb.delete_item(
        TableName=table, Key={"pk": {"S": "d-or-pass"}}, Expected=_expected("10"),
        ConditionalOperator="OR",
    )
    assert get("d-or-pass") is None, "DeleteItem OR with exactly one condition true left the item"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
