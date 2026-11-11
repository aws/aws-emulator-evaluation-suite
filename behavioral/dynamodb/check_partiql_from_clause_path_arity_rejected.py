"""partiql-from-clause-path-arity-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-from-clause-path-arity-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """(Error.Code, Error.Message) the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the statement to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL FROM path with 3 components, or an empty index component, is a top-level
    ValidationException with no effect on the item or on a subsequent well-formed statement.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.select.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ddb.put_item(TableName=table, Item={"pk": {"S": "a"}, "sk": {"S": "1"}, "val": {"S": "orig"}})

    three_component = f'SELECT * FROM "{table}"."idx"."extra" WHERE pk = \'a\' AND sk = \'1\''
    code, message = _error(lambda: ddb.execute_statement(Statement=three_component))
    assert code == "ValidationException", f"3-component SELECT: expected ValidationException, got {code}"
    expected_arity_msg = "A path may contain at most 2 components in the FROM clause"
    assert message == expected_arity_msg, f"3-component SELECT: unexpected message {message!r}"

    empty_index = f'SELECT * FROM "{table}"."" WHERE pk = \'a\' AND sk = \'1\''
    code, message = _error(lambda: ddb.execute_statement(Statement=empty_index))
    assert code == "ValidationException", f"empty-index SELECT: expected ValidationException, got {code}"
    expected_empty_msg = "Path component cannot be an empty string"
    assert message == expected_empty_msg, f"empty-index SELECT: unexpected message {message!r}"

    three_component_delete = f'DELETE FROM "{table}"."idx"."extra" WHERE pk = \'a\' AND sk = \'1\''
    code, message = _error(lambda: ddb.execute_statement(Statement=three_component_delete))
    assert code == "ValidationException", f"3-component DELETE: expected ValidationException, got {code}"
    assert message == expected_arity_msg, f"3-component DELETE: unexpected message {message!r}"

    empty_index_delete = f'DELETE FROM "{table}"."" WHERE pk = \'a\' AND sk = \'1\''
    code, message = _error(lambda: ddb.execute_statement(Statement=empty_index_delete))
    assert code == "ValidationException", f"empty-index DELETE: expected ValidationException, got {code}"
    assert message == expected_empty_msg, f"empty-index DELETE: unexpected message {message!r}"

    item = ddb.get_item(TableName=table, Key={"pk": {"S": "a"}, "sk": {"S": "1"}}, ConsistentRead=True)["Item"]
    assert item == {"pk": {"S": "a"}, "sk": {"S": "1"}, "val": {"S": "orig"}}, (
        f"the rejected DELETE statements must leave the item unchanged, got {item!r}"
    )

    # Positive control: the table's data plane is unaffected by the four rejections.
    still_works = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk = \'a\' AND sk = \'1\''
    )["Items"]
    assert still_works == [{"pk": {"S": "a"}, "sk": {"S": "1"}, "val": {"S": "orig"}}], (
        f"a well-formed statement after the rejections should still succeed, got {still_works!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
