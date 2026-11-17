"""execute-statement-in-operator-with-101-operands-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-in-operator-with-101-operands-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _table(ctx) -> str:
    """A pk/sk table for PartiQL SELECT statements."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-pqin-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _error(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"call unexpectedly SUCCEEDED where ValidationException was required: {resp!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL WHERE clause's IN predicate is refused past 100 operands; 100 is the accepted
    boundary and still selects every matching item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.operators.html
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx)
    for i in range(3):
        ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": f"a{i}"}, "status": {"S": f"s{i}"}})

    over = f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND status IN (' + ", ".join(f"?" for _ in range(101)) + ")"
    over_params = [{"S": f"s{i}"} for i in range(101)]
    code, message = _error(lambda: ddb.execute_statement(Statement=over, Parameters=over_params))
    expected = (
        "ValidationException",
        "The IN operator is provided with too many operands; number of operands: 101",
    )
    assert (code, message) == expected, (
        f"the 101-operand IN raised {(code, message)!r}, expected {expected!r}"
    )

    boundary = f'SELECT * FROM "{t}" WHERE pk=\'p1\' AND status IN (' + ", ".join("?" for _ in range(100)) + ")"
    boundary_params = [{"S": f"s{i}"} for i in range(3)] + [{"S": f"unused{i}"} for i in range(97)]
    page = ddb.execute_statement(Statement=boundary, Parameters=boundary_params, ConsistentRead=True)
    matched = tuple(sorted(i["sk"]["S"] for i in page["Items"]))
    assert matched == ("a0", "a1", "a2"), (
        f"the 100-operand IN matched {matched!r}, expected every seeded item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
