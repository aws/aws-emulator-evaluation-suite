"""scan-filter-between-dangling-and-conjunct-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-between-dangling-and-conjunct-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_SEED_ITEMS = (
    {"id": {"S": "item1"}, "price": {"N": "15"}},
    {"id": {"S": "item2"}, "price": {"N": "25"}},
)
_VALUES = {":lo": {"N": "10"}, ":hi": {"N": "20"}}

#: Derived from the seed: the control's own predicate selects only item1.
_MATCH = tuple(sorted(i["id"]["S"] for i in _SEED_ITEMS if 10 <= int(i["price"]["N"]) <= 20))


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression ending in a dangling AND right after a BETWEEN clause, with no
    clause following it, is refused ValidationException rather than treated as the bare BETWEEN.
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)

    control = _scan(ddb, name, FilterExpression="price BETWEEN :lo AND :hi", ExpressionAttributeValues=_VALUES)
    assert _ids(control["items"]) == _MATCH, (
        f"the control 'price BETWEEN :lo AND :hi' returned {_ids(control['items'])!r}, expected {_MATCH!r}"
    )

    code, message = _error_code(
        lambda: ddb.scan(TableName=name, FilterExpression="price BETWEEN :lo AND :hi AND",
                          ExpressionAttributeValues=_VALUES, ConsistentRead=True)
    )
    assert code == "ValidationException", (
        f"the dangling trailing AND was refused {code!r} ({message!r}), expected ValidationException"
    )
    expected_message = (
        'Invalid FilterExpression: Syntax error; token: "<EOF>", near: "AND"'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    again = _scan(ddb, name, FilterExpression="price BETWEEN :lo AND :hi", ExpressionAttributeValues=_VALUES)
    assert _ids(again["items"]) == _MATCH, (
        f"after the refused Scan, the well-formed BETWEEN returned {_ids(again['items'])!r}, "
        f"expected {_MATCH!r} unchanged"
    )


def _make_table(ctx) -> str:
    """The table under a minted name: id (S) HASH, on demand."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbbtwd-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _seed(ctx, name: str, items=_SEED_ITEMS) -> None:
    """Seeds the table with ONE BatchWriteItem."""
    resp = ctx.client("dynamodb").batch_write_item(
        RequestItems={name: [{"PutRequest": {"Item": item}} for item in items]})
    assert resp["UnprocessedItems"] == {}, (
        f"BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed while seeding"
    )


def _scan(ddb, name: str, **kwargs) -> dict:
    """Every page of a strongly consistent Scan: the items plus the summed Count and ScannedCount."""
    out = {"items": [], "count": 0, "scanned": 0, "pages": []}
    start = None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=name, ConsistentRead=True, **kwargs, **extra)
        out["items"].extend(page.get("Items", []))
        out["count"] += page["Count"]
        out["scanned"] += page["ScannedCount"]
        out["pages"].append((page["Count"], page["ScannedCount"], "Items" in page))
        start = page.get("LastEvaluatedKey")
        if not start:
            return out


def _ids(items) -> tuple:
    return tuple(sorted(i["id"]["S"] for i in items))


def _error_code(fn) -> tuple:
    """(code, message) of the ClientError fn() raises. Raises when the call SUCCEEDS: real AWS rejects it."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
