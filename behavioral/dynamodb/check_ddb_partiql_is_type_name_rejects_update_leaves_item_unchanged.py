"""ddb-partiql-is-type-name-rejects-update-leaves-item-unchanged."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ddb-partiql-is-type-name-rejects-update-leaves-item-unchanged"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_PK = "item1"
_UNSUPPORTED_TYPE = "INT4"
_UNSUPPORTED_TYPE_LABEL = "Integer4Type"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PartiQL UPDATE whose WHERE clause holds a matching `attr IS <type name>` predicate applies
    the write; an IS predicate naming an unsupported type is ValidationException naming that type
    and leaves the item unchanged.
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    ddb.put_item(TableName=name, Item={"pk": {"S": _PK}, "flag": {"BOOL": True}, "counter": {"N": "1"}})

    # Positive control: a supported type name in an UPDATE's WHERE clause runs as a filter and the
    # write that matches it is applied.
    ddb.execute_statement(
        Statement=f"UPDATE \"{name}\" SET counter = 2 WHERE pk = '{_PK}' AND flag IS BOOL"
    )
    after_control = ddb.get_item(TableName=name, Key={"pk": {"S": _PK}}, ConsistentRead=True)["Item"]
    assert after_control["counter"] == {"N": "2"}, (
        f"UPDATE ... WHERE flag IS BOOL left counter={after_control['counter']!r}, expected "
        f"{{'N': '2'}} -- the matching write was not applied"
    )

    # The exact message names the unsupported type and its position in the statement; the
    # position is this statement's, computed here rather than pinned, so it holds for any
    # generated table name length.
    statement = (
        f"UPDATE \"{name}\" SET counter = 3 WHERE pk = '{_PK}' AND x IS {_UNSUPPORTED_TYPE}"
    )
    predicate = f"x IS {_UNSUPPORTED_TYPE}"
    column = statement.index(predicate) + 1
    _IS_TYPE_REJECTED = (
        "ValidationException",
        f"Unsupported data type for IS operator: {_UNSUPPORTED_TYPE_LABEL}. Supported data types "
        f"are [MISSING, NULL, BOOLEAN, BLOB, STRING, NUMERIC, STRUCT, TUPLE, LIST] at 1:{column}:1",
    )

    def attempt():
        return ddb.execute_statement(Statement=statement)

    expect_error(attempt, *_IS_TYPE_REJECTED)

    after_rejection = ddb.get_item(TableName=name, Key={"pk": {"S": _PK}}, ConsistentRead=True)["Item"]
    assert after_rejection["counter"] == {"N": "2"}, (
        f"counter is {after_rejection['counter']!r} after the rejected UPDATE, expected the "
        f"unchanged {{'N': '2'}} from the control write -- the rejected statement must not write"
    )


def _make_table(ctx) -> str:
    """An on-demand table keyed by pk (S) HASH only."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-ddbistype-upd-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def expect_error(fn, code: str, message: str) -> None:
    """Calls fn() and asserts it raises exactly (code, message). Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected code {code!r}, got {err['Code']!r}"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(f"expected ({code}, {message!r}); the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
