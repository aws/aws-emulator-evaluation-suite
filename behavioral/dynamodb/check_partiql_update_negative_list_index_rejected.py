"""partiql-update-negative-list-index-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "partiql-update-negative-list-index-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _error(fn):
    """The ``(Code, Message)`` ``fn`` raises. An unexpected success raises too, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the statement to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UPDATE ... SET on a negative list index is refused with the index named in the message
    and writes nothing; the identical statement against index 0 succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.update.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbneg-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    key = {"pk": {"S": "r1"}}
    ddb.put_item(TableName=table, Item={**key, "tags": {"L": [{"S": "a"}, {"S": "b"}]}})

    stmt = f'UPDATE "{table}" SET tags[-1] = ? WHERE pk = ? RETURNING MODIFIED NEW *'
    want_col = stmt.index("-1]") + 2
    want = ("ValidationException", f"List index is not within the allowable range; index: [-1] at 1:{want_col}:1")
    code, message = _error(
        lambda: ddb.execute_statement(Statement=stmt, Parameters=[{"S": "y"}, {"S": "r1"}])
    )
    assert (code, message) == want, f"SET tags[-1] answered {(code, message)!r}, expected {want!r}"

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged["tags"] == {"L": [{"S": "a"}, {"S": "b"}]}, (
        f"a refused SET must write nothing; tags is {unchanged['tags']!r}"
    )

    # Positive control: the identical statement against a non-negative index succeeds.
    ok = ddb.execute_statement(
        Statement=f'UPDATE "{table}" SET tags[0] = ? WHERE pk = ? RETURNING MODIFIED NEW *',
        Parameters=[{"S": "y"}, {"S": "r1"}],
    )["Items"]
    assert ok == [{"tags": {"L": [{"S": "y"}]}}], f"SET tags[0] returned {ok!r}"
    stored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert stored["tags"] == {"L": [{"S": "y"}, {"S": "b"}]}, (
        f"stored tags after SET tags[0] is {stored['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
