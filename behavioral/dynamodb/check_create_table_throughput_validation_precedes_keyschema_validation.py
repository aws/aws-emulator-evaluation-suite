"""create-table-throughput-validation-precedes-keyschema-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-table-throughput-validation-precedes-keyschema-validation"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"

_DUP_HASH_KEY_SCHEMA = [
    {"AttributeName": "pk", "KeyType": "HASH"},
    {"AttributeName": "pk", "KeyType": "HASH"},
]
_KEY_SCHEMA_MESSAGE = "Invalid KeySchema: Some index key attribute have no definition"


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; returns only on not_found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_refused(ddb, ctx, table, **kwargs):
    """The (code, message) CreateTable is refused with; a table it creates anyway is torn down."""
    try:
        created = ddb.create_table(TableName=table, **kwargs)
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    raise AssertionError(f"CreateTable was accepted: {created['TableDescription']!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


def _assert_no_table(ddb, table):
    code, msg = _error(lambda: ddb.describe_table(TableName=table))
    assert code == "ResourceNotFoundException", f"a rejected CreateTable left a table behind: {code!r}: {msg!r}"
    expected = f"Requested resource not found: Table: {table} not found"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTable answers a missing or stray ProvisionedThroughput before an invalid KeySchema in
    the same request; resolving the throughput mismatch exposes the KeySchema error underneath.
    """
    ddb = ctx.client("dynamodb")

    name1 = ctx.unique_name("sim2real-behav-ddb-prec-nobm-")
    code1, msg1 = _create_refused(
        ddb, ctx, name1,
        AttributeDefinitions=[],
        KeySchema=_DUP_HASH_KEY_SCHEMA,
    )
    assert code1 == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code1}"
    expected1 = (
        "One or more parameter values were invalid: ReadCapacityUnits and WriteCapacityUnits "
        "must both be specified when BillingMode is PROVISIONED"
    )
    assert msg1 == expected1, f"expected message {expected1!r}, got {msg1!r}"
    _assert_no_table(ddb, name1)

    name2 = ctx.unique_name("sim2real-behav-ddb-prec-ppr-")
    code2, msg2 = _create_refused(
        ddb, ctx, name2,
        AttributeDefinitions=[],
        KeySchema=_DUP_HASH_KEY_SCHEMA,
        BillingMode="PAY_PER_REQUEST",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )
    assert code2 == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code2}"
    expected2 = (
        "One or more parameter values were invalid: Neither ReadCapacityUnits nor "
        "WriteCapacityUnits can be specified when BillingMode is PAY_PER_REQUEST"
    )
    assert msg2 == expected2, f"expected message {expected2!r}, got {msg2!r}"
    _assert_no_table(ddb, name2)

    name3 = ctx.unique_name("sim2real-behav-ddb-prec-ks-")
    code3, msg3 = _create_refused(
        ddb, ctx, name3,
        AttributeDefinitions=[],
        KeySchema=_DUP_HASH_KEY_SCHEMA,
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )
    assert code3 == ERR_VALIDATION, f"expected {ERR_VALIDATION}, got {code3}"
    assert msg3 == _KEY_SCHEMA_MESSAGE, f"expected message {_KEY_SCHEMA_MESSAGE!r}, got {msg3!r}"
    _assert_no_table(ddb, name3)

    name4 = ctx.unique_name("sim2real-behav-ddb-prec-ok-")
    ddb.create_table(
        TableName=name4,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name4), "ResourceNotFoundException"))
    deadline = time.monotonic() + 300.0
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=name4)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            break
        time.sleep(2)
    assert desc is not None and desc["TableStatus"] == "ACTIVE", f"positive control not ACTIVE: {desc!r}"
    throughput = desc.get("ProvisionedThroughput", {})
    assert (throughput.get("ReadCapacityUnits"), throughput.get("WriteCapacityUnits")) == (5, 5), (
        f"expected explicit throughput 5/5 to be honored, got {throughput!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
