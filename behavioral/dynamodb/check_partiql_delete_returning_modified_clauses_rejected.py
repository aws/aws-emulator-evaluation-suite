"""partiql-delete-returning-modified-clauses-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-delete-returning-modified-clauses-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _message_for(clause: str) -> str:
    return (
        f"Invalid returning clause: RETURNING {clause}. "
        "Only RETURNING ALL OLD * is allowed in DELETE statements."
    )


def _error(fn):
    """The (Code, Message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the statement to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DELETE ... RETURNING MODIFIED NEW * and RETURNING MODIFIED OLD * are each refused with a
    ValidationException naming the clause, deleting nothing; RETURNING ALL OLD * on the same item
    still removes it and returns the removed item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.delete.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqldelmod-")
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

    key_new = {"pk": {"S": "p1"}, "sk": {"S": "s1"}}
    item_new = {**key_new, "name": {"S": "Ada"}, "qty": {"N": "3"}}
    ddb.put_item(TableName=table, Item=item_new)

    key_old = {"pk": {"S": "p2"}, "sk": {"S": "s2"}}
    item_old = {**key_old, "name": {"S": "Bea"}, "qty": {"N": "5"}}
    ddb.put_item(TableName=table, Item=item_old)

    where_new = "WHERE pk = 'p1' AND sk = 's1'"
    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'DELETE FROM "{table}" {where_new} RETURNING MODIFIED NEW *'))
    assert code == "ValidationException", (
        f"DELETE ... RETURNING MODIFIED NEW * must be refused with ValidationException, got {code!r}"
    )
    expected_new = _message_for("MODIFIED NEW *")
    assert message == expected_new, f"expected message {expected_new!r}, got {message!r}"
    kept_new = ddb.get_item(TableName=table, Key=key_new, ConsistentRead=True).get("Item")
    assert kept_new == item_new, (
        f"the refused DELETE must leave the item intact; it now reads {kept_new!r}"
    )

    where_old = "WHERE pk = 'p2' AND sk = 's2'"
    code, message = _error(lambda: ddb.execute_statement(
        Statement=f'DELETE FROM "{table}" {where_old} RETURNING MODIFIED OLD *'))
    assert code == "ValidationException", (
        f"DELETE ... RETURNING MODIFIED OLD * must be refused with ValidationException, got {code!r}"
    )
    expected_old = _message_for("MODIFIED OLD *")
    assert message == expected_old, f"expected message {expected_old!r}, got {message!r}"
    kept_old = ddb.get_item(TableName=table, Key=key_old, ConsistentRead=True).get("Item")
    assert kept_old == item_old, (
        f"the refused DELETE must leave the item intact; it now reads {kept_old!r}"
    )

    # Positive control: the valid RETURNING form of the same DELETE removes the item.
    removed = ddb.execute_statement(Statement=f'DELETE FROM "{table}" {where_new} RETURNING ALL OLD *')
    assert removed["Items"] == [item_new], (
        f"DELETE ... RETURNING ALL OLD * must return the removed item {[item_new]!r}, got "
        f"{removed['Items']!r}"
    )
    gone = ddb.get_item(TableName=table, Key=key_new, ConsistentRead=True).get("Item")
    assert gone is None, f"the valid DELETE must remove the item, a consistent read found {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
