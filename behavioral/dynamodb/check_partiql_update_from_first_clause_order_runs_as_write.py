"""partiql-update-from-first-clause-order-runs-as-write."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-update-from-first-clause-order-runs-as-write"
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


def _stored(ddb, table, pk, sk):
    return ddb.get_item(
        TableName=table, Key={"pk": {"S": pk}, "sk": {"S": sk}}, ConsistentRead=True
    ).get("Item")


def expect_error(fn, code, message):
    """Assert ``fn`` is refused with the exact ``(code, message)`` pair."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected {code!r}, got {err['Code']!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the statement to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE statement that opens with FROM instead of UPDATE applies a SET and a
    REMOVE; an extra WHERE predicate is a write condition, an absent key raises
    ConditionalCheckFailedException creating nothing, and the form also runs in a batch and a transaction.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlfromfirst-")
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
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    item = {"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "active"}, "extra": {"S": "e1"}}
    ddb.put_item(TableName=table, Item=item)

    # 1. FROM-first form, keywords mixed case, ? parameters, SET then REMOVE, RETURNING ALL NEW *.
    r1 = ddb.execute_statement(
        Statement=f'from "{table}" where pk = ? and sk = ? set status = ? remove extra returning all new *',
        Parameters=[{"S": "p1"}, {"S": "s1"}, {"S": "changed"}],
    )
    want1 = [{"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "changed"}}]
    assert r1["Items"] == want1, f"RETURNING ALL NEW * after the FROM-first UPDATE returned {r1['Items']!r}"
    assert _stored(ddb, table, "p1", "s1") == want1[0], (
        f"the stored item after the FROM-first UPDATE is {_stored(ddb, table, 'p1', 's1')!r}"
    )

    # 2. An extra WHERE predicate is a write condition: false leaves the item untouched.
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"FROM \"{table}\" WHERE pk = 'p1' AND sk = 's1' AND status = 'nope' SET status = 'wrong'"
        ),
        *_CCF,
    )
    assert _stored(ddb, table, "p1", "s1") == want1[0], (
        f"a false extra predicate must leave the item untouched, got {_stored(ddb, table, 'p1', 's1')!r}"
    )

    # Positive control: the same predicate, true, applies.
    ddb.execute_statement(
        Statement=f"FROM \"{table}\" WHERE pk = 'p1' AND sk = 's1' AND status = 'changed' SET status = 'confirmed'"
    )
    confirmed = {"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "confirmed"}}
    assert _stored(ddb, table, "p1", "s1") == confirmed, (
        f"a true extra predicate must apply, got {_stored(ddb, table, 'p1', 's1')!r}"
    )

    # 3. An absent key raises ConditionalCheckFailedException and creates nothing.
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f"FROM \"{table}\" WHERE pk = 'absent' AND sk = 'absent' SET status = 'x'"
        ),
        *_CCF,
    )
    assert _stored(ddb, table, "absent", "absent") is None, (
        "the absent key must not have been created by the refused FROM-first UPDATE"
    )

    # 4. The FROM-first form runs as a BatchExecuteStatement member with no Error on the slot.
    batch = ddb.batch_execute_statement(
        Statements=[
            {"Statement": f"FROM \"{table}\" WHERE pk = 'p1' AND sk = 's1' SET status = 'batched'"}
        ]
    )
    assert "Error" not in batch["Responses"][0], f"the batch slot carried an error: {batch['Responses'][0]!r}"
    batched = {"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "batched"}}
    assert _stored(ddb, table, "p1", "s1") == batched, (
        f"the BatchExecuteStatement member must have applied, got {_stored(ddb, table, 'p1', 's1')!r}"
    )

    # 5. The FROM-first form runs inside ExecuteTransaction, and the transaction commits.
    ddb.execute_transaction(
        TransactStatements=[
            {"Statement": f"FROM \"{table}\" WHERE pk = 'p1' AND sk = 's1' SET status = 'transacted'"}
        ]
    )
    transacted = {"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "transacted"}}
    assert _stored(ddb, table, "p1", "s1") == transacted, (
        f"the ExecuteTransaction member must have committed, got {_stored(ddb, table, 'p1', 's1')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
