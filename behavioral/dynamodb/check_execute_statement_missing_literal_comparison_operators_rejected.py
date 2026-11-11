"""execute-statement-missing-literal-comparison-operators-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "execute-statement-missing-literal-comparison-operators-rejected"
GROUP = "data-plane"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ExecuteStatement refuses `=`, `<>` and `<` against the MISSING literal with one
    ValidationException naming IS as the only comparator for it.

    `=` against a real value still runs, and the table's items are unchanged after every refusal.
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx, "missop")
    _seed(ctx, name)

    _REFUSAL = ("ValidationException", "MISSING must be compared using IS operator")

    for op in ("=", "<>", "<"):
        got = _error(lambda op=op: ddb.execute_statement(
            Statement=f'SELECT id FROM "{name}" WHERE "status" {op} MISSING',
            ConsistentRead=True,
        ))
        assert got == _REFUSAL, (
            f'"status" {op} MISSING raised {got!r}, expected {_REFUSAL!r}'
        )

    control = ddb.execute_statement(
        Statement=f'SELECT id FROM "{name}" WHERE "status" = \'active\'', ConsistentRead=True,
    )
    control_ids = _ids(control["Items"])
    assert control_ids == ("user-001",), (
        f'"status" = \'active\' returned {control_ids!r}, expected only (\'user-001\',) -- the '
        f"operator itself works, only MISSING triggers the refusal"
    )

    after = _scan(ddb, name)
    after_ids = _ids(after)
    assert after_ids == _ALL, (
        f"the table holds {after_ids!r} after the refused statements, expected the seed "
        f"unchanged {_ALL!r}"
    )


#: Two items under an `id` (S) + `timestamp` (N) key; one carries the sparse `status` attribute.
_SEED_ITEMS = (
    {"id": {"S": "user-001"}, "timestamp": {"N": "1700000000"}, "status": {"S": "active"},
     "name": {"S": "John Doe"}},
    {"id": {"S": "user-002"}, "timestamp": {"N": "1700000001"}, "name": {"S": "Jane Doe"}},
)

_ALL = tuple(sorted(i["id"]["S"] for i in _SEED_ITEMS))


def _make_table(ctx, label: str) -> str:
    """An on-demand table keyed by id (S) HASH + timestamp (N) RANGE."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name(f"sim2real-ddbsfa-{label}-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"},
                   {"AttributeName": "timestamp", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"},
                              {"AttributeName": "timestamp", "AttributeType": "N"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _seed(ctx, name: str, items=_SEED_ITEMS) -> None:
    """Write the seed items in one BatchWriteItem."""
    resp = ctx.client("dynamodb").batch_write_item(
        RequestItems={name: [{"PutRequest": {"Item": item}} for item in items]})
    assert resp["UnprocessedItems"] == {}, (
        f"BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed while seeding"
    )


def _scan(ddb, name: str) -> list:
    """Every item of a strongly consistent Scan, paginated."""
    items, start = [], None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=name, ConsistentRead=True, **extra)
        items.extend(page["Items"])
        start = page.get("LastEvaluatedKey")
        if not start:
            return items


def _ids(items) -> tuple:
    return tuple(sorted(i["id"]["S"] for i in items))


def _error(fn) -> tuple:
    """The (code, message) ``fn`` raises; an unexpected success raises instead."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
