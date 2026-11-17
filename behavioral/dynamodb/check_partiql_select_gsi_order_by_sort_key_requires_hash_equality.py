"""partiql-select-gsi-order-by-sort-key-requires-hash-equality."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "partiql-select-gsi-order-by-sort-key-requires-hash-equality"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_NO_HASH_KEY = (
    "ValidationException",
    "Must have at least one non-optional hash key condition in WHERE clause when using ORDER BY clause.",
)
_NO_WHERE = (
    "ValidationException",
    "Must have WHERE clause in the statement when using ORDER BY clause.",
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(read, done, *, budget_s: float, poll_s: float):
    deadline = time.monotonic() + budget_s
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {budget_s}s; last value {value!r}")
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SELECT through a GSI qualifier with hash-key equality and ORDER BY on the index sort key
    returns items in that sort-key order; without a hash-key equality condition, or without a
    WHERE clause at all, the same ORDER BY is refused with its exact message.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqgob-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gpk", "AttributeType": "S"},
            {"AttributeName": "gsk", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi1",
                "KeySchema": [
                    {"AttributeName": "gpk", "KeyType": "HASH"},
                    {"AttributeName": "gsk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _poll(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE" and all(g["IndexStatus"] == "ACTIVE" for g in t["GlobalSecondaryIndexes"]),
        budget_s=_budget_s(ctx, 600.0), poll_s=5.0,
    )

    # Partition g1 holds three items whose gsk values are not in insertion order, so a correct
    # ascending/descending answer cannot come from echoing insertion order.
    main_items = [
        {"pk": {"S": "p1"}, "sk": {"S": "a"}, "gpk": {"S": "g1"}, "gsk": {"N": "30"}, "tag": {"S": "t"}},
        {"pk": {"S": "p2"}, "sk": {"S": "b"}, "gpk": {"S": "g1"}, "gsk": {"N": "10"}, "tag": {"S": "t"}},
        {"pk": {"S": "p3"}, "sk": {"S": "c"}, "gpk": {"S": "g1"}, "gsk": {"N": "20"}, "tag": {"S": "t"}},
    ]
    # A sibling partition the WHERE equality must exclude.
    sibling = {"pk": {"S": "p4"}, "sk": {"S": "d"}, "gpk": {"S": "g2"}, "gsk": {"N": "15"}, "tag": {"S": "t"}}
    for item in main_items + [sibling]:
        ddb.put_item(TableName=table, Item=item)

    # The GSI fans out asynchronously: poll until every written item, sibling included, is in it.
    written = sorted(main_items + [sibling], key=lambda i: i["gsk"]["N"])
    _poll(
        lambda: sorted(ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."gsi1"')["Items"],
                       key=lambda i: i["gsk"]["N"]),
        lambda items: items == written,
        budget_s=_budget_s(ctx, 60.0), poll_s=2.0,
    )

    ascending = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}"."gsi1" WHERE gpk = \'g1\' ORDER BY gsk ASC'
    )["Items"]
    want_asc = sorted(main_items, key=lambda i: int(i["gsk"]["N"]))
    assert ascending == want_asc, (
        f"ORDER BY gsk ASC through the GSI must return gsk 10, 20, 30 in that order.\n"
        f"want: {want_asc!r}\ngot:  {ascending!r}"
    )

    descending = ddb.execute_statement(
        Statement=f'SELECT * FROM "{table}"."gsi1" WHERE gpk = \'g1\' ORDER BY gsk DESC'
    )["Items"]
    want_desc = sorted(main_items, key=lambda i: int(i["gsk"]["N"]), reverse=True)
    assert descending == want_desc, (
        f"ORDER BY gsk DESC through the GSI must return gsk 30, 20, 10 in that order.\n"
        f"want: {want_desc!r}\ngot:  {descending!r}"
    )

    # Positive control: the same non-key filter, without ORDER BY, succeeds through the GSI and
    # returns every tagged item regardless of partition - so the refusal below is about ORDER BY,
    # not about this filter shape.
    filtered = ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."gsi1" WHERE tag = \'t\'')["Items"]
    assert sorted(filtered, key=lambda i: i["gsk"]["N"]) == sorted(main_items + [sibling], key=lambda i: i["gsk"]["N"]), (
        f"a non-key filter without ORDER BY must return every matching item, got {filtered!r}"
    )

    expect_error(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."gsi1" WHERE tag = \'t\' ORDER BY gsk ASC'),
        *_NO_HASH_KEY,
    )
    expect_error(
        lambda: ddb.execute_statement(Statement=f'SELECT * FROM "{table}"."gsi1" ORDER BY gsk ASC'),
        *_NO_WHERE,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
