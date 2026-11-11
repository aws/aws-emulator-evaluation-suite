"""key-condition-illegal-sort-key-operator-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "key-condition-illegal-sort-key-operator-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0

def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where an error was required: {resp!r}")


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"dynamodb table {table_name!r} could not be deleted: {code}"
                ) from exc
            return


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A KeyConditionExpression rejects `<>`/`OR` and an operand type the sort key cannot take --
    `begins_with`, `<` and `BETWEEN` given an N or a BOOL operand against an S sort key, or any
    of these against an N one -- with ValidationException, while the legal form still succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, table))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            break
        time.sleep(2.0)
    assert status == "ACTIVE", f"table {table!r} not ACTIVE within budget: {status!r}"

    for sk in (1, 2, 3, 10, 11):
        ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"N": str(sk)}})

    values = {":p": {"S": "p"}, ":s": {"N": "1"}}
    # All three forms are legal in a FilterExpression, just not in a key condition.
    invalid_operator = (
        "Invalid KeyConditionExpression: Invalid operator used in KeyConditionExpression"
    )
    for label, expr, expected in (
        ("not-equal", "pk = :p AND sk <> :s", invalid_operator),
        ("or", "pk = :p OR sk = :s", invalid_operator),
        (
            "begins_with on N", "pk = :p AND begins_with(sk, :s)",
            "Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
            "operator or function: begins_with, operand type: N",
        ),
    ):
        code, message = _error(lambda expr=expr: ddb.query(
            TableName=table, KeyConditionExpression=expr, ExpressionAttributeValues=values,
        ))
        assert code == "ValidationException", (
            f"KeyConditionExpression {expr!r} ({label}) answered {code!r} ({message!r}), expected "
            f"ValidationException -- this form is legal in a FilterExpression, never in a key "
            f"condition"
        )
        assert message == expected, (
            f"the {label} refusal's message is {message!r}, expected {expected!r}"
        )

    # Positive control: a legal sort-key operator over the same partition.
    items = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND sk > :s",
        ExpressionAttributeValues=values, ConsistentRead=True,
    )["Items"]
    got = [int(i["sk"]["N"]) for i in items]
    assert got == [2, 3, 10, 11], (
        f"Query pk = p AND sk > 1 returned sort keys {got!r}; expected [2, 3, 10, 11] in NUMERIC "
        f"order"
    )

    # --- The same operand-type validation holds against an S sort key: begins_with(), `<` and
    # BETWEEN refuse an N or a BOOL operand, not just the non-key-condition operators above. ---
    table_s = ctx.unique_name("sim2real-behav-ddb-strsk-")
    ddb.create_table(
        TableName=table_s,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, table_s))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status_s = None
    while time.monotonic() < deadline:
        status_s = ddb.describe_table(TableName=table_s)["Table"]["TableStatus"]
        if status_s == "ACTIVE":
            break
        time.sleep(2.0)
    assert status_s == "ACTIVE", f"table {table_s!r} not ACTIVE within budget: {status_s!r}"

    for sk in ("a", "b", "c"):
        ddb.put_item(TableName=table_s, Item={"pk": {"S": "p"}, "sk": {"S": sk}})

    mismatched = (
        (
            "begins_with with an N operand", "pk = :p AND begins_with(sk, :s)",
            {":p": {"S": "p"}, ":s": {"N": "1"}},
            "Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
            "operator or function: begins_with, operand type: N",
        ),
        (
            "begins_with with a BOOL operand", "pk = :p AND begins_with(sk, :s)",
            {":p": {"S": "p"}, ":s": {"BOOL": True}},
            "Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
            "operator or function: begins_with, operand type: BOOL",
        ),
        (
            "< with an N operand", "pk = :p AND sk < :s",
            {":p": {"S": "p"}, ":s": {"N": "1"}},
            "One or more parameter values were invalid: Condition parameter type does not match "
            "schema type",
        ),
        (
            "< with a BOOL operand", "pk = :p AND sk < :s",
            {":p": {"S": "p"}, ":s": {"BOOL": True}},
            "Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
            "operator or function: <, operand type: BOOL",
        ),
        (
            "BETWEEN with an N lower bound", "pk = :p AND sk BETWEEN :s1 AND :s2",
            {":p": {"S": "p"}, ":s1": {"N": "1"}, ":s2": {"S": "z"}},
            "Invalid KeyConditionExpression: The BETWEEN operator requires same data type for "
            "lower and upper bounds; lower bound operand: AttributeValue: {N:1}, upper bound "
            "operand: AttributeValue: {S:z}",
        ),
        (
            "BETWEEN with a BOOL lower bound", "pk = :p AND sk BETWEEN :s1 AND :s2",
            {":p": {"S": "p"}, ":s1": {"BOOL": True}, ":s2": {"S": "z"}},
            "Invalid KeyConditionExpression: Incorrect operand type for operator or function; "
            "operator or function: BETWEEN, operand type: BOOL",
        ),
    )
    for label, expr, values, expected in mismatched:
        code, message = _error(lambda expr=expr, values=values: ddb.query(
            TableName=table_s, KeyConditionExpression=expr, ExpressionAttributeValues=values,
        ))
        assert code == "ValidationException", (
            f"KeyConditionExpression {expr!r} ({label}) against an S sort key answered {code!r} "
            f"({message!r}), expected ValidationException"
        )
        assert message == expected, (
            f"the {label} refusal's message against an S sort key is {message!r}, expected "
            f"{expected!r}"
        )

    # Positive control: the same operators are legal with an operand of the sort key's own type.
    begins = ddb.query(
        TableName=table_s, KeyConditionExpression="pk = :p AND begins_with(sk, :s)",
        ExpressionAttributeValues={":p": {"S": "p"}, ":s": {"S": "a"}}, ConsistentRead=True,
    )["Items"]
    assert [i["sk"]["S"] for i in begins] == ["a"], (
        f"begins_with(sk, 'a') against the S sort key returned {begins!r}; expected just 'a'"
    )
    between = ddb.query(
        TableName=table_s, KeyConditionExpression="pk = :p AND sk BETWEEN :s1 AND :s2",
        ExpressionAttributeValues={":p": {"S": "p"}, ":s1": {"S": "a"}, ":s2": {"S": "b"}},
        ConsistentRead=True,
    )["Items"]
    assert [i["sk"]["S"] for i in between] == ["a", "b"], (
        f"sk BETWEEN 'a' AND 'b' against the S sort key returned {between!r}; expected ['a', 'b']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
