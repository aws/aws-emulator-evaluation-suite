"""get-item-key-with-attribute-outside-schema-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-item-key-with-attribute-outside-schema-rejected"
GROUP = "validation"
SERVICES = ["dynamodb"]

_ERR_VALIDATION = "ValidationException"
_ERR_MESSAGE = "The provided key element does not match the schema"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """GetItem whose Key carries an attribute outside the table's key schema is refused with
    ValidationException; the same item read by its exact key still succeeds.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_GetItem.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-key-schema-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table),
                              "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    key = {"pk": {"S": "p1"}}
    ddb.put_item(TableName=table, Item={**key, "v": {"S": "val"}})

    code, message = _error(lambda: ddb.get_item(
        TableName=table, Key={"pk": {"S": "p1"}, "extra": {"S": "x"}}, ConsistentRead=True,
    ))
    assert code == _ERR_VALIDATION, f"expected {_ERR_VALIDATION}, got {code!r}: {message!r}"
    assert message == _ERR_MESSAGE, f"expected message {_ERR_MESSAGE!r}, got {message!r}"

    ok = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert ok == {**key, "v": {"S": "val"}}, f"a fully-specified key returned {ok!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
