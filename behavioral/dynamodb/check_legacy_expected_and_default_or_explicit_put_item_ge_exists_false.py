"""legacy-expected-and-default-or-explicit-put-item-ge-exists-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-expected-and-default-or-explicit-put-item-ge-exists-false"
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
    """A two-condition legacy Expected (score GE threshold, extra Exists:false) on PutItem is
    ANDed when ConditionalOperator is omitted and ORed under ConditionalOperator='OR': AND needs
    both true or raises ConditionalCheckFailedException; OR lands when either is true.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.ConditionalOperator.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-legcondput-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def seed(pk: str, score: str, extra_present: bool) -> None:
        item = {"pk": {"S": pk}, "score": {"N": score}}
        if extra_present:
            item["extra"] = {"S": "present"}
        ddb.put_item(TableName=table, Item=item)

    def get(pk: str):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    # --- default AND (ConditionalOperator omitted): both conditions true -> lands ---
    seed("and-pass", "50", extra_present=False)  # score GE 10 true, extra Exists:false true
    replacement = {"pk": {"S": "and-pass"}, "score": {"N": "50"}, "note": {"S": "replaced"}}
    ddb.put_item(TableName=table, Item=replacement, Expected=_expected("10"))
    got = get("and-pass")
    assert got == replacement, f"PutItem default-AND with both conditions true did not land: {got!r}"

    # --- default AND: extra present makes Exists:false false -> refused, nothing changes ---
    original = {"pk": {"S": "and-fail"}, "score": {"N": "50"}, "extra": {"S": "present"}}
    seed("and-fail", "50", extra_present=True)
    expect_error(lambda: ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "and-fail"}, "score": {"N": "50"}, "extra": {"S": "present"},
              "note": {"S": "replaced"}},
        Expected=_expected("10"),
    ), *_CCFE)
    got = get("and-fail")
    assert got == original, f"PutItem default-AND refusal must leave the item untouched: {got!r}"

    # --- explicit OR: score GE 10 false, extra Exists:false true -> exactly one true, lands ---
    seed("or-pass", "5", extra_present=False)
    replacement_or = {"pk": {"S": "or-pass"}, "score": {"N": "5"}, "note": {"S": "replaced"}}
    ddb.put_item(TableName=table, Item=replacement_or, Expected=_expected("10"), ConditionalOperator="OR")
    got = get("or-pass")
    assert got == replacement_or, f"PutItem OR with exactly one condition true did not land: {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
