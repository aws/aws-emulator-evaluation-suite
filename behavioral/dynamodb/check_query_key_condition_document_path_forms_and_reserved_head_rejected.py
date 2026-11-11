"""query-key-condition-document-path-forms-and-reserved-head-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-key-condition-document-path-forms-and-reserved-head-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_NESTED = "Invalid KeyConditionExpression: KeyConditionExpressions cannot have conditions on nested attributes"
_RESERVED_DATA = "Invalid KeyConditionExpression: Attribute name is a reserved keyword; reserved keyword: data"

# (KeyConditionExpression, ExpressionAttributeValues, ExpressionAttributeNames)
_NESTED_FORMS = [
    ("pk.foo = :v", {":v": {"S": "u"}}, None),
    ("pk[0] = :v", {":v": {"S": "u"}}, None),
    ("pk = :p AND sk.foo = :v", {":p": {"S": "u"}, ":v": {"S": "m"}}, None),
    ("pk = :p AND sk[0] = :v", {":p": {"S": "u"}, ":v": {"S": "m"}}, None),
    ("pk = :p AND begins_with(sk.foo, :v)", {":p": {"S": "u"}, ":v": {"S": "m"}}, None),
    ("pk = :p AND sk.foo BETWEEN :v AND :w", {":p": {"S": "u"}, ":v": {"S": "a"}, ":w": {"S": "z"}}, None),
    ("pk = :p AND :v < sk.foo", {":p": {"S": "u"}, ":v": {"S": "a"}}, None),
    ("pk.foo > :v", {":v": {"S": "u"}}, None),
    ("foo.bar = :v", {":v": {"S": "u"}}, None),
    ("#d.foo = :v", {":v": {"S": "u"}}, {"#d": "pk"}),
]


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
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


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key condition addressing an attribute through a document path (dot, list index, inside a
    function, BETWEEN or value-first) is refused as nested; a reserved word head is refused first.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.KeyConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-kcenest-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    item = {"pk": {"S": "u"}, "sk": {"S": "m"}}
    ddb.put_item(TableName=table, Item=item)

    # Positive control: the top-level key paths select the item.
    ok = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p AND sk = :v", ConsistentRead=True,
        ExpressionAttributeValues={":p": {"S": "u"}, ":v": {"S": "m"}},
    )
    assert ok["Items"] == [item], f"Query 'pk = :p AND sk = :v' returned {ok['Items']!r}"

    for kce, values, names in _NESTED_FORMS:
        kwargs = {"TableName": table, "KeyConditionExpression": kce, "ExpressionAttributeValues": values}
        if names:
            kwargs["ExpressionAttributeNames"] = names
        code, msg = _error(lambda kwargs=kwargs: ddb.query(**kwargs))
        assert (code, msg) == ("ValidationException", _NESTED), (
            f"KeyConditionExpression {kce!r} gave {code!r}: {msg!r}"
        )

    code, msg = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="data.foo = :v", ExpressionAttributeValues={":v": {"S": "u"}},
    ))
    assert (code, msg) == ("ValidationException", _RESERVED_DATA), (
        f"KeyConditionExpression 'data.foo = :v' gave {code!r}: {msg!r}"
    )

    rows = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert rows == [item], f"the table changed across the refused queries: {rows!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
