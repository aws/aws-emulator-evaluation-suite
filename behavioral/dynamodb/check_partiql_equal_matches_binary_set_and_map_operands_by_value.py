"""partiql-equal-matches-binary-set-and-map-operands-by-value."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-equal-matches-binary-set-and-map-operands-by-value"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL = and <> compare Binary, Set and NULL parameters by exact value and type; a String
    Set or Map matches = regardless of member or key order, a List only in stored order; the
    same equality agrees as an UpdateItem ConditionExpression and a PartiQL UPDATE condition.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-operators.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlnonscalar-")
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
        "bval": {"B": b"hello"},
        "bsval": {"BS": [b"a", b"b"]},
        "nsval": {"NS": ["1", "2"]},
        "nullval": {"NULL": True},
        "ssval": {"SS": ["a", "b"]},
        "mval": {"M": {"x": {"N": "1"}, "y": {"N": "2"}}},
        "lval": {"L": [{"N": "1"}, {"N": "2"}]},
    }
    for pk, val in rows.items():
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "val": val})
    all_pks = set(rows)

    # B: = matches the equal stored value, not a different one; <> is the exact complement.
    matched = _select_pks(ddb, table, "val = ?", [{"B": b"hello"}])
    assert matched == {"bval"}, f"B = matched {sorted(matched)!r}, expected ['bval']"
    mismatched = _select_pks(ddb, table, "val = ?", [{"B": b"world"}])
    assert mismatched == set(), f"B = against a different value matched {sorted(mismatched)!r}, expected none"
    not_matched = _select_pks(ddb, table, "val <> ?", [{"B": b"hello"}])
    assert not_matched == all_pks - {"bval"}, (
        f"B <> matched {sorted(not_matched)!r}, expected everything but bval"
    )

    # BS and NS: a parameter permuted in member order still matches =.
    matched = _select_pks(ddb, table, "val = ?", [{"BS": [b"b", b"a"]}])
    assert matched == {"bsval"}, f"permuted BS = matched {sorted(matched)!r}, expected ['bsval']"
    matched = _select_pks(ddb, table, "val = ?", [{"NS": ["2", "1"]}])
    assert matched == {"nsval"}, f"permuted NS = matched {sorted(matched)!r}, expected ['nsval']"

    # NULL: = matches a stored NULL and nothing else.
    matched = _select_pks(ddb, table, "val = ?", [{"NULL": True}])
    assert matched == {"nullval"}, f"NULL = matched {sorted(matched)!r}, expected ['nullval']"

    # M: permuted key order still matches =; a differing value under one key does not.
    matched = _select_pks(ddb, table, "val = ?", [{"M": {"y": {"N": "2"}, "x": {"N": "1"}}}])
    assert matched == {"mval"}, f"permuted M = matched {sorted(matched)!r}, expected ['mval']"
    mismatched = _select_pks(ddb, table, "val = ?", [{"M": {"x": {"N": "1"}, "y": {"N": "99"}}}])
    assert mismatched == set(), f"M = against a changed value matched {sorted(mismatched)!r}, expected none"

    # L: = matches only the stored element order.
    matched = _select_pks(ddb, table, "val = ?", [{"L": [{"N": "1"}, {"N": "2"}]}])
    assert matched == {"lval"}, f"L = in stored order matched {sorted(matched)!r}, expected ['lval']"
    reordered = _select_pks(ddb, table, "val = ?", [{"L": [{"N": "2"}, {"N": "1"}]}])
    assert reordered == set(), f"L = reordered matched {sorted(reordered)!r}, expected none"

    # The same equality agrees as an UpdateItem ConditionExpression: a permuted SS applies.
    ddb.update_item(
        TableName=table, Key={"pk": {"S": "ssval"}},
        UpdateExpression="SET marker = :m",
        ConditionExpression="val = :v",
        ExpressionAttributeValues={":m": {"S": "via-updateitem"}, ":v": {"SS": ["b", "a"]}},
    )
    after = ddb.get_item(TableName=table, Key={"pk": {"S": "ssval"}}, ConsistentRead=True)["Item"]
    assert after["marker"] == {"S": "via-updateitem"}, (
        f"UpdateItem's ConditionExpression on a permuted SS must have applied, got {after.get('marker')!r}"
    )

    # And as a PartiQL UPDATE write condition: a permuted SS fires the write.
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET marker2 = ? WHERE pk = ? AND val = ?',
        Parameters=[{"S": "via-partiql"}, {"S": "ssval"}, {"SS": ["b", "a"]}],
    )
    after = ddb.get_item(TableName=table, Key={"pk": {"S": "ssval"}}, ConsistentRead=True)["Item"]
    assert after["marker2"] == {"S": "via-partiql"}, (
        f"the PartiQL UPDATE WHERE condition on a permuted SS must have applied, got {after.get('marker2')!r}"
    )

    # A mismatched M as the write condition raises ConditionalCheckFailedException, item unchanged.
    before = ddb.get_item(TableName=table, Key={"pk": {"S": "mval"}}, ConsistentRead=True)["Item"]
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET marker3 = ? WHERE pk = ? AND val = ?',
            Parameters=[{"S": "should-not-apply"}, {"S": "mval"}, {"M": {"x": {"N": "1"}, "y": {"N": "99"}}}],
        ),
        *_CCF,
    )
    after = ddb.get_item(TableName=table, Key={"pk": {"S": "mval"}}, ConsistentRead=True)["Item"]
    assert after == before, f"a mismatched M write condition must leave the item untouched, got {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
