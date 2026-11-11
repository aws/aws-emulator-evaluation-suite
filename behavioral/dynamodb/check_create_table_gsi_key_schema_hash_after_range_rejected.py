"""create-table-gsi-key-schema-hash-after-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-gsi-key-schema-hash-after-range-rejected"
GROUP = "tables"
SERVICES = ["dynamodb"]

_HASH_AFTER_RANGE_MESSAGE = (
    "One or more parameter values were invalid: All HASH key attributes must precede RANGE key "
    "attributes in the KeySchema"
)
_INDEX = "by-a-b-c"


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


def _create_refused(ddb, ctx, table, **kwargs):
    """The (code, message) CreateTable is refused with; a table it creates anyway is torn down."""
    try:
        created = ddb.create_table(TableName=table, BillingMode="PAY_PER_REQUEST", **kwargs)
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    raise AssertionError(f"CreateTable was accepted: {created['TableDescription']!r}")


def _assert_absent(ddb, table):
    code, msg = _error(lambda: ddb.describe_table(TableName=table))
    want = ("ResourceNotFoundException", f"Requested resource not found: Table: {table} not found")
    assert (code, msg) == want, f"the refused table {table} describes as {code!r}: {msg!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable refuses a GSI KeySchema with a HASH attribute after the RANGE one and creates
    nothing; the same attributes keyed HASH, HASH, RANGE create a GSI described in that order.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html
    """
    ddb = ctx.client("dynamodb")
    base = ctx.unique_name("sim2real-behav-ddb-ks-")

    order = f"{base}-order"
    code, msg = _create_refused(
        ddb, ctx, order,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("pk", "a", "b", "c")],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[{
            "IndexName": _INDEX,
            "KeySchema": [
                {"AttributeName": "a", "KeyType": "HASH"},
                {"AttributeName": "b", "KeyType": "RANGE"},
                {"AttributeName": "c", "KeyType": "HASH"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    assert (code, msg) == ("ValidationException", _HASH_AFTER_RANGE_MESSAGE), (
        f"a GSI KeySchema HASH, RANGE, HASH gave {code!r}: {msg!r}"
    )
    _assert_absent(ddb, order)

    good = f"{base}-good"
    ordered = [
        {"AttributeName": "a", "KeyType": "HASH"},
        {"AttributeName": "c", "KeyType": "HASH"},
        {"AttributeName": "b", "KeyType": "RANGE"},
    ]
    ddb.create_table(
        TableName=good,
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("pk", "a", "b", "c")],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[{"IndexName": _INDEX, "KeySchema": ordered, "Projection": {"ProjectionType": "ALL"}}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=good), "ResourceNotFoundException"))
    desc = _wait_active(ddb, ctx, good)
    assert desc["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}], f"base key is {desc['KeySchema']!r}"
    gsis = {g["IndexName"]: g["KeySchema"] for g in desc["GlobalSecondaryIndexes"]}
    assert gsis == {_INDEX: ordered}, f"the GSI with the RANGE attribute last describes as {gsis!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
