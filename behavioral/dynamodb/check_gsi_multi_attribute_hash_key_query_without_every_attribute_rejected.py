"""gsi-multi-attribute-hash-key-query-without-every-attribute-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gsi-multi-attribute-hash-key-query-without-every-attribute-rejected"
GROUP = "gsi"
SERVICES = ["dynamodb"]

_INDEX = "by-tenant-region"


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


def _error(fn):
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _pks(ddb, **query) -> list:
    items = []
    for page in ddb.get_paginator("query").paginate(**query):
        items.extend(page["Items"])
    return sorted(i["pk"]["S"] for i in items)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI keyed on two HASH attributes answers a Query only with equality on both (either alone raises
    ValidationException naming the other), returns exactly the matching items and skips an item missing one;
    CreateTable with five HASH attributes raises ValidationException and creates nothing.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-mak-")

    # --- negative at create time: more HASH attributes than allowed, nothing is created ---
    too_many = f"{table}-five"
    attrs5 = ["tenant", "region", "ts", "a4", "a5"]
    try:
        created = ddb.create_table(
            TableName=too_many,
            AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ["pk", *attrs5]],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[{
                "IndexName": "five-hash",
                "KeySchema": [{"AttributeName": n, "KeyType": "HASH"} for n in attrs5],
                "Projection": {"ProjectionType": "ALL"},
            }],
        )
    except ClientError as exc:
        code, msg = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    else:
        ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=too_many), "ResourceNotFoundException"))
        raise AssertionError(f"a GSI with five HASH attributes was accepted: {created['TableDescription']['TableStatus']!r}")
    assert code == "ValidationException", f"five HASH attributes gave {code!r}"
    assert msg == (
        "One or more parameter values were invalid: The KeySchema exceeds the maximum allowed number of HASH key attributes"
    ), f"five HASH attributes: message {msg!r}"
    code, msg = _error(lambda: ddb.describe_table(TableName=too_many))
    assert (code, msg) == ("ResourceNotFoundException", f"Requested resource not found: Table: {too_many} not found"), (
        f"the refused table describes as {code!r}: {msg!r}, expected it absent"
    )

    # --- positive context: a two-HASH-attribute GSI with a RANGE attribute ---
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ["pk", "tenant", "region", "ts"]],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [
                {"AttributeName": "tenant", "KeyType": "HASH"},
                {"AttributeName": "region", "KeyType": "HASH"},
                {"AttributeName": "ts", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    desc = _poll(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE" and all(g["IndexStatus"] == "ACTIVE" for g in t["GlobalSecondaryIndexes"]),
        budget_s=600.0, poll_s=5.0,
    )
    key_schema = desc["GlobalSecondaryIndexes"][0]["KeySchema"]
    assert key_schema == [
        {"AttributeName": "tenant", "KeyType": "HASH"},
        {"AttributeName": "region", "KeyType": "HASH"},
        {"AttributeName": "ts", "KeyType": "RANGE"},
    ], f"the GSI describes its key as {key_schema!r}"

    rows = [("1", "acme", "eu", "01"), ("2", "acme", "us", "02"), ("3", "acme", "eu", "03"), ("4", "zeta", "eu", "04")]
    for pk, tenant, region, ts in rows:
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "tenant": {"S": tenant}, "region": {"S": region}, "ts": {"S": ts}})
    # Missing one HASH attribute: the item is not indexed at all.
    ddb.put_item(TableName=table, Item={"pk": {"S": "5"}, "tenant": {"S": "acme"}, "ts": {"S": "05"}})

    names = {"#r": "region"}
    full = dict(
        TableName=table, IndexName=_INDEX, KeyConditionExpression="tenant = :t AND #r = :r",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":t": {"S": "acme"}, ":r": {"S": "eu"}},
    )
    got = _poll(lambda: _pks(ddb, **full), lambda v: v == ["1", "3"], budget_s=60.0, poll_s=2.0)
    assert got == ["1", "3"], f"the full index key selected {got!r}"
    ranged = dict(full, KeyConditionExpression="tenant = :t AND #r = :r AND ts > :x",
                  ExpressionAttributeValues={":t": {"S": "acme"}, ":r": {"S": "eu"}, ":x": {"S": "01"}})
    got = _pks(ddb, **ranged)
    assert got == ["3"], f"the full index key with ts > '01' selected {got!r}, expected only '3'"

    indexed = _poll(
        lambda: sorted(i["pk"]["S"] for p in ddb.get_paginator("scan").paginate(TableName=table, IndexName=_INDEX) for i in p["Items"]),
        lambda v: v == ["1", "2", "3", "4"], budget_s=60.0, poll_s=2.0,
    )
    assert "5" not in indexed, f"an item without the 'region' HASH attribute was indexed: {indexed!r}"

    # --- negatives: one HASH attribute alone is refused, naming the missing one ---
    code, msg = _error(lambda: ddb.query(
        TableName=table, IndexName=_INDEX, KeyConditionExpression="tenant = :t",
        ExpressionAttributeValues={":t": {"S": "acme"}},
    ))
    assert code == "ValidationException", f"querying with only 'tenant' gave {code!r}"
    assert msg == "HASH key attributes region must have equality conditions specified in the query", (
        f"querying with only 'tenant': message {msg!r}"
    )
    code, msg = _error(lambda: ddb.query(
        TableName=table, IndexName=_INDEX, KeyConditionExpression="#r = :r",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":r": {"S": "eu"}},
    ))
    assert code == "ValidationException", f"querying with only 'region' gave {code!r}"
    assert msg == "HASH key attributes tenant must have equality conditions specified in the query", (
        f"querying with only 'region': message {msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
