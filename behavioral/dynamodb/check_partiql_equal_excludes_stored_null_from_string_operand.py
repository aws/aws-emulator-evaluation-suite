"""partiql-equal-excludes-stored-null-from-string-operand."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-equal-excludes-stored-null-from-string-operand"
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


def _select_pks(ddb, table, where, params):
    items = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE {where}', Parameters=params, ConsistentRead=True
    )["Items"]
    return {i["pk"]["S"] for i in items}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE WHERE condition comparing a stored NULL-typed attribute to a String
    operand with = is refused as a failed condition, leaving the item unchanged, because = does
    not treat a stored NULL as equal to a non-NULL value; a matching String condition applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlnulleq-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    rows = {
        "nullval": {"NULL": True},
        "strval": {"S": "x"},
    }
    for pk, val in rows.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "val": val})
    all_pks = set(rows)

    # A String operand matches only the stored String, never the stored NULL.
    matched = _select_pks(ddb, table, "val = ?", [{"S": "x"}])
    assert matched == {"strval"}, f"String = matched {sorted(matched)!r}, expected ['strval']"
    not_matched = _select_pks(ddb, table, "val <> ?", [{"S": "x"}])
    assert not_matched == all_pks - {"strval"}, (
        f"String <> matched {sorted(not_matched)!r}, expected everything but strval"
    )

    # A NULL operand matches only the stored NULL, never the stored String.
    matched = _select_pks(ddb, table, "val = ?", [{"NULL": True}])
    assert matched == {"nullval"}, f"NULL = matched {sorted(matched)!r}, expected ['nullval']"
    not_matched = _select_pks(ddb, table, "val <> ?", [{"NULL": True}])
    assert not_matched == all_pks - {"nullval"}, (
        f"NULL <> matched {sorted(not_matched)!r}, expected everything but nullval"
    )

    # The same comparison agrees as a PartiQL UPDATE write condition: a NULL item does not
    # satisfy `val = <String>`, so the write is refused and the item stays as it was.
    before = ddb.get_item(TableName=table, Key={"pk": {"S": "nullval"}}, ConsistentRead=True)["Item"]
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET marker = ? WHERE pk = ? AND val = ?',
            Parameters=[{"S": "should-not-apply"}, {"S": "nullval"}, {"S": "x"}],
        ),
        *_CCF,
    )
    after = ddb.get_item(TableName=table, Key={"pk": {"S": "nullval"}}, ConsistentRead=True)["Item"]
    assert after == before, f"a String write condition against a stored NULL must leave the item untouched, got {after!r}"

    # Positive control: the matching String condition applies to the String item.
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET marker = ? WHERE pk = ? AND val = ?',
        Parameters=[{"S": "applied"}, {"S": "strval"}, {"S": "x"}],
    )
    after = ddb.get_item(TableName=table, Key={"pk": {"S": "strval"}}, ConsistentRead=True)["Item"]
    assert after["marker"] == {"S": "applied"}, (
        f"the matching String UPDATE WHERE condition must have applied, got {after.get('marker')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
