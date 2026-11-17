"""partiql-update-where-ors-bare-partition-branch-with-negated-sort-key-branch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-where-ors-bare-partition-branch-with-negated-sort-key-branch-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_MISSING_KEY = (
    "ValidationException",
    "Where clause does not contain a mandatory equality on all key attributes",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _stored(ddb, table, pk, sk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}, "sk": {"S": sk}},
                        ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE whose WHERE ORs a bare partition-key branch with a negated sort-key
    branch is rejected with the mandatory key-equality ValidationException; nothing is written.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlupdor-")
    ddb.create_table(
        TableName=table,
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
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    seed = {"pk": {"S": "x"}, "sk": {"S": "y"}, "a": {"N": "0"}}
    ddb.put_item(TableName=table, Item=seed)

    # Neither OR branch carries an equality on both key attributes (one names only pk, the other
    # negates sk), so the WHERE has no mandatory key equality and the statement is rejected.
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"UPDATE \"{table}\" SET a=1 WHERE pk='x' OR pk='x' AND NOT sk='z'"
        ),
        *_MISSING_KEY,
    )
    unchanged = _stored(ddb, table, "x", "y")
    assert unchanged == seed, f"a rejected UPDATE changed the existing item: {unchanged!r}"

    # Positive control: the identical SET succeeds once the WHERE is a plain key equality with
    # no OR at all.
    ddb.execute_statement(Statement=f"UPDATE \"{table}\" SET a=1 WHERE pk='x' AND sk='y'")
    updated = _stored(ddb, table, "x", "y")
    assert updated == {"pk": {"S": "x"}, "sk": {"S": "y"}, "a": {"N": "1"}}, (
        f"UPDATE with a plain key-equality WHERE did not land: {updated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
