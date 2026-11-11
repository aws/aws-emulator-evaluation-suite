"""execute-statement-limit-clause-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-limit-clause-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement rejects a PartiQL SELECT carrying a LIMIT clause, a SQL clause
    DynamoDB's PartiQL grammar does not support, naming the clause and its exact position."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=t, Item={"pk": {"S": "item"}})

    # Positive control: the same SELECT, with no LIMIT clause, is well-formed PartiQL.
    control = ddb.execute_statement(Statement=f'SELECT * FROM "{t}"')
    assert [i["pk"]["S"] for i in control["Items"]] == ["item"], (
        f"the unlimited SELECT returned {control['Items']!r}, expected the one seeded item"
    )

    statement = f'SELECT * FROM "{t}" LIMIT 1'
    offset = statement.index("LIMIT")
    expected_message = f"Unsupported clause: LIMIT at 1:{offset + 7}:1"
    code, message = _error(lambda: ddb.execute_statement(Statement=statement))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
