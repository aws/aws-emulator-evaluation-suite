"""expression-attribute-map-key-syntax-and-length-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "expression-attribute-map-key-syntax-and-length-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_EAN_SYNTAX_MSG = 'ExpressionAttributeNames contains invalid key: Syntax error; key: "{key}"'
_EAV_SYNTAX_MSG = 'ExpressionAttributeValues contains invalid key: Syntax error; key: "{key}"'
_EAN_TOO_LONG_MSG = (
    "ExpressionAttributeNames contains invalid key: The expression attribute map contains a key "
    "that is too long; size of key: {size}"
)
_EAV_TOO_LONG_MSG = (
    "ExpressionAttributeValues contains invalid key: The expression attribute map contains a key "
    "that is too long; size of key: 256"
)
_EAN_EMPTY_VALUE_MSG = "ExpressionAttributeNames contains invalid value: Empty attribute name for key #a"


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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A placeholder key that is only its prefix, holds an invalid character or exceeds 255 bytes, or
    a name mapped to "", is ValidationException on GetItem and Scan; a valid key is accepted.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ExpressionAttributeNames.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-eamap-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    key = {"pk": {"S": "k1"}}
    ddb.put_item(TableName=table, Item={**key, "foo": {"S": "a"}, "bar": {"S": "b"}})

    def get(projection, names):
        return ddb.get_item(TableName=table, Key=key, ProjectionExpression=projection,
                            ExpressionAttributeNames=names, ConsistentRead=True)

    def scan(condition, values):
        return ddb.scan(TableName=table, FilterExpression=condition, ExpressionAttributeValues=values)

    long_name = "#" + "a" * 255
    long_bad_name = "#" + "a" * 255 + "-x"
    long_value = ":" + "a" * 255
    cases = [
        ("GetItem with name key '#'", _EAN_SYNTAX_MSG.format(key="#"),
         lambda: get("#", {"#": "foo"})),
        ("GetItem with name key '#a-b'", _EAN_SYNTAX_MSG.format(key="#a-b"),
         lambda: get("#a", {"#a-b": "foo"})),
        ("GetItem with a 256-byte name key", _EAN_TOO_LONG_MSG.format(size=256),
         lambda: get("#a", {long_name: "foo"})),
        ("GetItem with a 258-byte name key holding '-'", _EAN_TOO_LONG_MSG.format(size=258),
         lambda: get("#a", {long_bad_name: "foo"})),
        ("GetItem with name #a mapped to ''", _EAN_EMPTY_VALUE_MSG,
         lambda: get("#a", {"#a": ""})),
        ("Scan with value key ':'", _EAV_SYNTAX_MSG.format(key=":"),
         lambda: scan("foo = :", {":": {"S": "x"}})),
        ("Scan with value key ':a-b'", _EAV_SYNTAX_MSG.format(key=":a-b"),
         lambda: scan("foo = :v", {":a-b": {"S": "x"}})),
        ("Scan with a 256-byte value key", _EAV_TOO_LONG_MSG,
         lambda: scan("foo = :v", {long_value: {"S": "x"}})),
    ]
    for label, want, fn in cases:
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    got = get("#a_1", {"#a_1": "foo"}).get("Item")
    assert got == {"foo": {"S": "a"}}, f"GetItem projecting #a_1 -> foo returned {got!r}"
    page = ddb.scan(TableName=table, FilterExpression="foo = :v_1",
                    ExpressionAttributeValues={":v_1": {"S": "a"}}, ConsistentRead=True)
    assert page["Count"] == 1, f"Scan filtering foo = :v_1 counted {page['Count']!r}: {page['Items']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
