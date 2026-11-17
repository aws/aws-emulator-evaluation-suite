"""scan-filter-ordering-comparators-reject-list-and-map-operands."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-ordering-comparators-reject-list-and-map-operands"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_LIST_VAL = {"L": [{"S": "x"}]}
_MAP_VAL = {"M": {"a": {"S": "1"}}}

#: Every ordering comparator the FilterExpression grammar supports besides = and <>.
_ORDERING_OPS = ("<", "<=", ">", ">=")


def _make_table(ctx) -> str:
    """An on-demand table keyed by pk (S) HASH only."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-ddbcmp-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _error_code(fn) -> tuple:
    """``(code, message)`` fn() raises. Raises when the call SUCCEEDS: real AWS rejects it."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _eq_count(ddb, name: str, val: dict) -> int:
    return ddb.scan(TableName=name, FilterExpression="val = :v", ExpressionAttributeValues={":v": val},
                    ConsistentRead=True, Select="COUNT")["Count"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan's FilterExpression refuses <, <=, > and >= on a List operand and > on a Map operand
    with the operand-type ValidationException naming the operator and the type, while = on the
    List operand matches the same item before and after the refusals.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    ddb.put_item(TableName=name, Item={"pk": {"S": "item-l"}, "val": _LIST_VAL})
    ddb.put_item(TableName=name, Item={"pk": {"S": "item-m"}, "val": _MAP_VAL})

    # Positive control, taken before any rejection: equality matches the List attribute exactly.
    before = _eq_count(ddb, name, _LIST_VAL)
    assert before == 1, f"'val = :v' on the List operand matched {before}, expected 1"

    for op in _ORDERING_OPS:
        code, message = _error_code(lambda op=op: ddb.scan(
            TableName=name, FilterExpression=f"val {op} :v", ExpressionAttributeValues={":v": _LIST_VAL},
            ConsistentRead=True,
        ))
        assert code == "ValidationException", f"'val {op} :v' on a List raised {code!r} ({message!r})"
        expected = (
            f"Invalid FilterExpression: Incorrect operand type for operator or function; "
            f"operator or function: {op}, operand type: L"
        )
        assert message == expected, f"'val {op} :v' on a List raised message {message!r}, expected {expected!r}"

    # The same ordering comparator refuses a Map operand too -- it is not List-specific.
    code, message = _error_code(lambda: ddb.scan(
        TableName=name, FilterExpression="val > :v", ExpressionAttributeValues={":v": _MAP_VAL},
        ConsistentRead=True,
    ))
    assert code == "ValidationException", f"'val > :v' on a Map raised {code!r} ({message!r})"
    expected_m = (
        "Invalid FilterExpression: Incorrect operand type for operator or function; "
        "operator or function: >, operand type: M"
    )
    assert message == expected_m, f"'val > :v' on a Map raised message {message!r}, expected {expected_m!r}"

    # The effect is absent and the table is unaffected: the same equality control still matches.
    after = _eq_count(ddb, name, _LIST_VAL)
    assert after == before, f"the equality control matched {after} after the rejections, expected {before}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
