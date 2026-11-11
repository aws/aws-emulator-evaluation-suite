"""partiql-update-set-subtraction-applies-and-multiply-divide-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-set-subtraction-applies-and-multiply-divide-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_MUL = ("ValidationException", "Unsupported operator in Update Expression. Operator: *")
_DIV = ("ValidationException", "Unsupported operator in Update Expression. Operator: /")

_WAIT_S = 60.0


def _wait_active(ddb, table):
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + _WAIT_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE within {_WAIT_S:.0f}s; last status {status!r}")


def expect_error(fn, code, message):
    """Call fn() and grade the ClientError it raises on exact code and message."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
        assert (got_code, got_message) == (code, message), (
            f"expected {(code, message)!r}, got {(got_code, got_message)!r}"
        )
        return
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it succeeded: {result!r}")


def _stored(ddb, table, pk, sk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}, "sk": {"S": sk}},
                        ConsistentRead=True)["Item"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE SET applies + and - arithmetic in place, but * and / are each a
    ValidationException naming the operator, and the stored value is unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbsetarith-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_active(ddb, table)

    pk, sk = "p1", "s1"
    ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{\'pk\': ?, \'sk\': ?, \'n\': ?}}',
        Parameters=[{"S": pk}, {"S": sk}, {"N": "20"}],
    )

    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET n = n - ? WHERE pk = ? AND sk = ?',
        Parameters=[{"N": "5"}, {"S": pk}, {"S": sk}],
    )
    after_sub = _stored(ddb, table, pk, sk)
    assert after_sub["n"] == {"N": "15"}, f"SET n = n - 5 from n=20 gave {after_sub.get('n')!r}, expected N 15"

    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET n = n * ? WHERE pk = ? AND sk = ?',
            Parameters=[{"N": "2"}, {"S": pk}, {"S": sk}]),
        *_MUL,
    )
    after_mul = _stored(ddb, table, pk, sk)
    assert after_mul["n"] == {"N": "15"}, f"the refused SET n = n * 2 changed n to {after_mul.get('n')!r}"

    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'UPDATE "{table}" SET n = n / ? WHERE pk = ? AND sk = ?',
            Parameters=[{"N": "2"}, {"S": pk}, {"S": sk}]),
        *_DIV,
    )
    after_div = _stored(ddb, table, pk, sk)
    assert after_div["n"] == {"N": "15"}, f"the refused SET n = n / 2 changed n to {after_div.get('n')!r}"

    # Positive control: the surviving + arithmetic still applies after both refusals.
    ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET n = n + ? WHERE pk = ? AND sk = ?',
        Parameters=[{"N": "5"}, {"S": pk}, {"S": sk}],
    )
    after_add = _stored(ddb, table, pk, sk)
    assert after_add["n"] == {"N": "20"}, f"SET n = n + 5 from n=15 gave {after_add.get('n')!r}, expected N 20"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
