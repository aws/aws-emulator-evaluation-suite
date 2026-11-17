"""scan-gsi-include-projection-unprojected-attribute-rejected-base-table-contrast."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-gsi-include-projection-unprojected-attribute-rejected-base-table-contrast"
GROUP = "access_path"
SERVICES = ["dynamodb"]

_INDEX = "status-index"
_NOT_PROJECTED = (
    "ValidationException",
    f"One or more parameter values were invalid: Global secondary index {_INDEX} does not project [details]",
)
_PROJECTED_SET = {"pk", "sk", "status", "createdAt", "summary"}


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; in-use is retried for a while."""
    def run_undo() -> None:
        deadline = time.monotonic() + 300.0
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table: str) -> None:
    """Poll DescribeTable until the table and every index are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan of an INCLUDE GSI refuses a ProjectionExpression naming a non-projected attribute,
    with or without Select=SPECIFIC_ATTRIBUTES, while one naming only projected attributes
    returns exactly that set for every indexed item, and a base table scan returns what it refused.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbgsiproj-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "createdAt", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"},
                          {"AttributeName": "createdAt", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["summary"]},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    items = {
        "ITEM#1": {"pk": {"S": "ITEM#1"}, "sk": {"S": "META"}, "status": {"S": "available"},
                   "createdAt": {"S": "2024-01-01T00:00:00Z"}, "summary": {"S": "Summary one"},
                   "details": {"S": "Detail one"}},
        "ITEM#2": {"pk": {"S": "ITEM#2"}, "sk": {"S": "META"}, "status": {"S": "pending"},
                   "createdAt": {"S": "2024-01-02T00:00:00Z"}, "summary": {"S": "Summary two"},
                   "details": {"S": "Detail two"}},
    }
    for item in items.values():
        ddb.put_item(TableName=table, Item=item)

    expect_error(
        lambda: ddb.scan(TableName=table, IndexName=_INDEX, ProjectionExpression="details"),
        *_NOT_PROJECTED,
    )
    expect_error(
        lambda: ddb.scan(TableName=table, IndexName=_INDEX, ProjectionExpression="details",
                         Select="SPECIFIC_ATTRIBUTES"),
        *_NOT_PROJECTED,
    )

    # The index is eventually consistent: poll until it serves both items.
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 60.0)
    idx_items: list = []
    while True:
        idx_items = ddb.scan(TableName=table, IndexName=_INDEX,
                             ProjectionExpression="pk, sk, #st, createdAt, summary",
                             ExpressionAttributeNames={"#st": "status"},
                             Select="SPECIFIC_ATTRIBUTES")["Items"]
        if len(idx_items) >= 2:
            break
        assert time.monotonic() < deadline, f"index scan stayed at {len(idx_items)} item(s): {idx_items!r}"
        time.sleep(2)
    assert len(idx_items) == 2, f"index scan returned {len(idx_items)} item(s), expected 2: {idx_items!r}"
    by_pk = {i["pk"]["S"]: i for i in idx_items}
    assert set(by_pk) == set(items), f"index scan returned keys {sorted(by_pk)}, expected {sorted(items)}"
    for pk, idx_item in by_pk.items():
        assert set(idx_item) == _PROJECTED_SET, (
            f"item {pk!r} from the index scan carried {sorted(idx_item)}, expected {sorted(_PROJECTED_SET)}"
        )
        assert idx_item["summary"] == items[pk]["summary"], (
            f"item {pk!r}'s projected summary was {idx_item['summary']!r}, expected {items[pk]['summary']!r}"
        )

    base_items = ddb.scan(TableName=table, ProjectionExpression="pk, sk, details",
                          ConsistentRead=True)["Items"]
    assert len(base_items) == 2, f"base table scan returned {len(base_items)} item(s), expected 2: {base_items!r}"
    base_by_pk = {i["pk"]["S"]: i for i in base_items}
    assert set(base_by_pk) == set(items), f"base table scan returned keys {sorted(base_by_pk)}, expected {sorted(items)}"
    for pk, base_item in base_by_pk.items():
        assert set(base_item) == {"pk", "sk", "details"}, (
            f"item {pk!r} from the base table scan carried {sorted(base_item)}, expected pk, sk, details"
        )
        assert base_item["details"] == items[pk]["details"], (
            f"item {pk!r}'s base table details were {base_item['details']!r}, expected {items[pk]['details']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
