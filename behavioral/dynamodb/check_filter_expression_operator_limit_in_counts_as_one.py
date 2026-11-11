"""filter-expression-operator-limit-in-counts-as-one."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-expression-operator-limit-in-counts-as-one"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]


def _equals_chain(n: int) -> str:
    """`n` `#a = :v` comparisons AND'd together: `2n-1` operators."""
    return " AND ".join(["#a = :v"] * n)


def _chain_with_in(n: int, in_operands: int) -> tuple:
    """`n` clauses AND'd where the last is an IN of `in_operands` values: still `2n-1` operators."""
    values = {":v": {"S": "v"}}
    clauses = ["#a = :v"] * (n - 1)
    operands = [f":w{i}" for i in range(in_operands)]
    clauses.append("#a IN (" + ", ".join(operands) + ")")
    for i, name in enumerate(operands):
        values[name] = {"S": f"other{i}"}
    return " AND ".join(clauses), values


def _error(fn) -> tuple:
    """(code, message) of the ClientError `fn()` raises; RAISES if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FilterExpression with 301 operators is rejected naming the count; 299 is accepted.

    An IN clause with many operands still counts as exactly one operator, so swapping one
    comparison for a 100-operand IN leaves the counts, and so the verdicts, unmoved.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "x"}, "a": {"S": "v"}})
    names = {"#a": "a"}

    code, message = _error(lambda: ddb.scan(
        TableName=table, FilterExpression=_equals_chain(151), ExpressionAttributeNames=names,
        ExpressionAttributeValues={":v": {"S": "v"}},
    ))
    expected = "Invalid FilterExpression: The expression contains too many operators; operator count: 301"
    assert (code, message) == ("ValidationException", expected), (
        f"a 301-operator FilterExpression raised {(code, message)!r}, expected "
        f"{('ValidationException', expected)!r}"
    )

    accepted = ddb.scan(
        TableName=table, FilterExpression=_equals_chain(150), ExpressionAttributeNames=names,
        ExpressionAttributeValues={":v": {"S": "v"}},
    )
    assert accepted["Count"] == 1, f"a 299-operator FilterExpression matched {accepted['Count']!r}, expected 1"

    expr_301_via_in, values_301 = _chain_with_in(151, 100)
    code2, message2 = _error(lambda: ddb.scan(
        TableName=table, FilterExpression=expr_301_via_in, ExpressionAttributeNames=names,
        ExpressionAttributeValues=values_301,
    ))
    assert (code2, message2) == ("ValidationException", expected), (
        f"151 clauses with a 100-operand IN raised {(code2, message2)!r}, expected the same "
        f"301-operator refusal {('ValidationException', expected)!r} — an IN must count as one operator"
    )

    expr_299_via_in, values_299 = _chain_with_in(150, 100)
    accepted_in = ddb.scan(
        TableName=table, FilterExpression=expr_299_via_in, ExpressionAttributeNames=names,
        ExpressionAttributeValues=values_299,
    )
    assert accepted_in["Count"] == 0, (
        f"150 clauses with a 100-operand IN matched {accepted_in['Count']!r}, expected 0 (none of "
        f"the IN operands equal the stored value)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
