"""partiql-update-where-and-updateitem-condition-expression-agree-on-equal-and-not-equal-for-sets-and-null."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-where-and-updateitem-condition-expression-agree-on-equal-and-not-equal-for-sets-and-null"
GROUP = "partiql"
SERVICES = ["dynamodb"]
_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    """Assert ``fn`` is refused with the exact ``(code, message)`` pair."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected {code!r}, got {err['Code']!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UpdateItem ConditionExpression and a PartiQL UPDATE ... WHERE clause agree on '=' and
    '<>' over a Binary Set, a Number Set, a String Set and NULL; each refusal is
    ConditionalCheckFailedException, leaving the item exactly as the prior write left it.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlcce-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    cases = {
        "bs": {"stored": {"BS": [b"aa", b"bb"]}, "match": {"BS": [b"bb", b"aa"]}, "mismatch": {"BS": [b"aa", b"cc"]}},
        "ns": {"stored": {"NS": ["1", "2"]}, "match": {"NS": ["2", "1"]}, "mismatch": {"NS": ["1", "3"]}},
        "ss": {"stored": {"SS": ["a", "b"]}, "match": {"SS": ["b", "a"]}, "mismatch": {"SS": ["a", "c"]}},
        "null": {"stored": {"NULL": True}, "match": {"NULL": True}, "mismatch": {"S": "not-null"}},
    }

    for name, spec in cases.items():
        pk = f"{name}-item"
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "val": spec["stored"]})

        # UpdateItem ConditionExpression '=' with the matching operand applies.
        ddb.update_item(
            TableName=table, Key={"pk": {"S": pk}},
            UpdateExpression="SET step1 = :s",
            ConditionExpression="val = :v",
            ExpressionAttributeValues={":s": {"S": "ui-eq-match"}, ":v": spec["match"]},
        )
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item["step1"] == {"S": "ui-eq-match"}, (
            f"{name}: UpdateItem ConditionExpression 'val = :v' with the matching operand must apply, got {item!r}"
        )

        # The same '=' as a PartiQL UPDATE ... WHERE condition applies too (agreement).
        ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET step2 = ? WHERE pk = ? AND val = ?',
            Parameters=[{"S": "pql-eq-match"}, {"S": pk}, spec["match"]],
        )
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item["step2"] == {"S": "pql-eq-match"}, (
            f"{name}: PartiQL UPDATE ... WHERE val = ? with the matching operand must apply, got {item!r}"
        )

        # UpdateItem ConditionExpression '<>' with the same matching operand is refused: val is
        # not '<>' a value it equals.
        before = dict(item)
        expect_error(lambda: ddb.update_item(
            TableName=table, Key={"pk": {"S": pk}},
            UpdateExpression="SET step3 = :s",
            ConditionExpression="val <> :v",
            ExpressionAttributeValues={":s": {"S": "should-not-apply"}, ":v": spec["match"]},
        ), *_CCF)
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item == before, (
            f"{name}: a refused UpdateItem ConditionExpression '<>' must leave the item unchanged, got {item!r}"
        )

        # The same '<>' as a PartiQL UPDATE ... WHERE condition is refused the same way (agreement).
        expect_error(lambda: ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET step3 = ? WHERE pk = ? AND val <> ?',
            Parameters=[{"S": "should-not-apply"}, {"S": pk}, spec["match"]],
        ), *_CCF)
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item == before, (
            f"{name}: a refused PartiQL UPDATE ... WHERE '<>' must leave the item unchanged, got {item!r}"
        )

        # UpdateItem ConditionExpression '<>' with a differing operand applies.
        ddb.update_item(
            TableName=table, Key={"pk": {"S": pk}},
            UpdateExpression="SET step4 = :s",
            ConditionExpression="val <> :v",
            ExpressionAttributeValues={":s": {"S": "ui-ne-mismatch"}, ":v": spec["mismatch"]},
        )
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item["step4"] == {"S": "ui-ne-mismatch"}, (
            f"{name}: UpdateItem ConditionExpression 'val <> :v' with a differing operand must apply, got {item!r}"
        )

        # The same '<>' as a PartiQL UPDATE ... WHERE condition applies too (agreement).
        ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET step5 = ? WHERE pk = ? AND val <> ?',
            Parameters=[{"S": "pql-ne-mismatch"}, {"S": pk}, spec["mismatch"]],
        )
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item["step5"] == {"S": "pql-ne-mismatch"}, (
            f"{name}: PartiQL UPDATE ... WHERE val <> ? with a differing operand must apply, got {item!r}"
        )

        # A mismatched '=' is refused on both surfaces and leaves the item exactly as the prior
        # successful write left it.
        before = dict(item)
        expect_error(lambda: ddb.update_item(
            TableName=table, Key={"pk": {"S": pk}},
            UpdateExpression="SET step6 = :s",
            ConditionExpression="val = :v",
            ExpressionAttributeValues={":s": {"S": "should-not-apply"}, ":v": spec["mismatch"]},
        ), *_CCF)
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item == before, (
            f"{name}: a refused UpdateItem ConditionExpression '=' must leave the item unchanged, got {item!r}"
        )

        expect_error(lambda: ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET step6 = ? WHERE pk = ? AND val = ?',
            Parameters=[{"S": "should-not-apply"}, {"S": pk}, spec["mismatch"]],
        ), *_CCF)
        item = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)["Item"]
        assert item == before, (
            f"{name}: a refused PartiQL UPDATE ... WHERE '=' must leave the item unchanged, got {item!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
