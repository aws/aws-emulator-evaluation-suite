"""execute-statement-select-multi-attribute-gsi-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-select-multi-attribute-gsi-key-rejected"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_MULTI_HASH = "multi-hash-index"
_MULTI_RANGE = "multi-range-index"
_SINGLE = "single-attr-index"
_LSI = "lsi1"

_MULTI_ATTR_ERROR = (
    "ValidationException",
    "PartiQL statements cannot be executed on tables with multi-attribute HASH keys or "
    "multi-attribute RANGE keys.",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str):
    """Assert ``fn`` raises exactly ``(code, message)``; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(read, done, *, budget_s: float, poll_s: float):
    """``read()`` once ``done(value)``; raises naming the last value when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {budget_s}s; last value {value!r}")
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PartiQL SELECT addressed at a GSI with a multi-attribute HASH or RANGE key is refused with
    ValidationException under every WHERE shape, but a syntax or literal/parameter conversion
    error is reported first; the base table, a single-attribute GSI and an LSI are unaffected.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pq-mak-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "tenant", "AttributeType": "S"},
            {"AttributeName": "region", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "S"},
            {"AttributeName": "seq", "AttributeType": "N"},
            {"AttributeName": "cat", "AttributeType": "S"},
            {"AttributeName": "category", "AttributeType": "S"},
            {"AttributeName": "lsk", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": _MULTI_HASH,
                "KeySchema": [
                    {"AttributeName": "tenant", "KeyType": "HASH"},
                    {"AttributeName": "region", "KeyType": "HASH"},
                    {"AttributeName": "ts", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": _MULTI_RANGE,
                "KeySchema": [
                    {"AttributeName": "cat", "KeyType": "HASH"},
                    {"AttributeName": "ts", "KeyType": "RANGE"},
                    {"AttributeName": "seq", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": _SINGLE,
                "KeySchema": [{"AttributeName": "category", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        LocalSecondaryIndexes=[
            {
                "IndexName": _LSI,
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "lsk", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    desc = _poll(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE" and all(g["IndexStatus"] == "ACTIVE" for g in t["GlobalSecondaryIndexes"]),
        budget_s=_budget_s(ctx, 600.0), poll_s=5.0,
    )
    assert len(desc["GlobalSecondaryIndexes"]) == 3, f"expected 3 GSIs active, got {desc['GlobalSecondaryIndexes']!r}"

    item = {
        "pk": {"S": "p1"}, "sk": {"S": "s1"}, "tenant": {"S": "acme"}, "region": {"S": "eu"},
        "ts": {"S": "01"}, "seq": {"N": "1"}, "cat": {"S": "c1"}, "category": {"S": "c1"},
        "lsk": {"N": "5"},
    }
    ddb.put_item(TableName=table, Item=item)

    # --- every SELECT shape against the two-HASH-attribute GSI gets the same refusal ---
    expect_error(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}"'), *_MULTI_ATTR_ERROR,
    )
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE tenant=\'acme\' AND region=\'eu\' ORDER BY ts DESC'
        ),
        *_MULTI_ATTR_ERROR,
    )
    expect_error(
        lambda: ddb.execute_statement(Statement=f'SELECT COUNT(*) FROM "{table}"."{_MULTI_HASH}"'), *_MULTI_ATTR_ERROR,
    )
    expect_error(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE category=\'c1\''),
        *_MULTI_ATTR_ERROR,
    )
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE tenant=5 AND region=\'eu\''
        ),
        *_MULTI_ATTR_ERROR,
    )
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE tenant = ? AND region = ?',
            Parameters=[{"N": "5"}, {"S": "eu"}],
        ),
        *_MULTI_ATTR_ERROR,
    )
    # A full, correctly typed key-equality query is refused the same way: there is no WHERE shape
    # that lets a SELECT through a multi-attribute-key GSI succeed.
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE tenant=\'acme\' AND region=\'eu\''
        ),
        *_MULTI_ATTR_ERROR,
    )

    # --- the two-RANGE-attribute GSI is refused the same way (representative probe) ---
    expect_error(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."{_MULTI_RANGE}" WHERE cat=\'c1\''),
        *_MULTI_ATTR_ERROR,
    )

    # --- a syntax error, and an unconvertible literal or parameter, are reported first ---
    expect_error(
        lambda: ddb.execute_statement(Statement=f'SELEKT * FROM "{table}"."{_MULTI_HASH}"'),
        "ValidationException",
        "Statement wasn't well formed, can't be processed: Expected data manipulation",
    )
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE tenant = \'acme, AND region=\'eu\''
        ),
        "ValidationException",
        "Statement wasn't well formed, can't be processed: ",
    )
    expect_error(
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE tenant = ? AND region = ?',
            Parameters=[{"N": "notanumber"}, {"S": "eu"}],
        ),
        "ValidationException",
        "The parameter cannot be converted to a numeric value: notanumber",
    )

    # --- positive controls: the base table, the single-attribute GSI and the LSI still work ---
    # The GSI fans out asynchronously: poll until the item reaches it.
    select = _poll(
        lambda: ddb.execute_statement(
            Statement=f'SELECT * FROM "{table}"."{_SINGLE}" WHERE category=\'c1\''
        )["Items"],
        lambda items: items == [item],
        budget_s=_budget_s(ctx, 60.0), poll_s=1.0,
    )
    assert select == [item], f"single-attribute GSI SELECT returned {select!r}"

    select = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}"."{_LSI}" WHERE pk=\'p1\'', ConsistentRead=True,
    )["Items"]
    assert select == [item], f"LSI SELECT returned {select!r}"

    select = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}" WHERE pk=\'p1\' AND sk=\'s1\'', ConsistentRead=True,
    )["Items"]
    assert select == [item], f"base-table SELECT returned {select!r}"

    ddb.execute_statement(Statement=f"INSERT INTO \"{table}\" VALUE {{'pk':'p2','sk':'s2'}}")
    inserted = ddb.get_item(TableName=table, Key={"pk": {"S": "p2"}, "sk": {"S": "s2"}}, ConsistentRead=True)
    assert inserted.get("Item") == {"pk": {"S": "p2"}, "sk": {"S": "s2"}}, (
        f"the base-table INSERT did not create the item, got {inserted!r}"
    )

    ddb.execute_statement(Statement=f"UPDATE \"{table}\" SET extra='x' WHERE pk='p2' AND sk='s2'")
    updated = ddb.get_item(TableName=table, Key={"pk": {"S": "p2"}, "sk": {"S": "s2"}}, ConsistentRead=True)["Item"]
    assert updated.get("extra") == {"S": "x"}, f"the base-table UPDATE did not apply, got {updated!r}"

    ddb.execute_statement(Statement=f"DELETE FROM \"{table}\" WHERE pk='p2' AND sk='s2'")
    deleted = ddb.get_item(TableName=table, Key={"pk": {"S": "p2"}, "sk": {"S": "s2"}}, ConsistentRead=True)
    assert "Item" not in deleted, "the base-table DELETE did not remove the item"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
