"""x-amz-crc32-matches-body-on-success-and-error."""
from __future__ import annotations

import time
import zlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "x-amz-crc32-matches-body-on-success-and-error"
GROUP = "wire-integrity"
SERVICES = ["dynamodb"]


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Every DynamoDB response, 200 or 400, carries an x-amz-crc32 header equal to the CRC32 of the raw body bytes,
    including a body with multi-byte UTF-8; SDKs that validate the header reject any other value.
    """
    ddb = ctx.client("dynamodb")
    seen: list = []

    def capture(operation_model=None, response_dict=None, **_kw):
        seen.append((operation_model.name, response_dict["status_code"],
                     dict(response_dict["headers"]), response_dict["body"]))

    ddb.meta.events.register("before-parse.dynamodb", capture)
    ctx.on_cleanup(lambda: ddb.meta.events.unregister("before-parse.dynamodb", capture))

    def last(op: str, status: int):
        assert seen, f"{op}: no response was captured"
        got_op, got_status, headers, body = seen[-1]
        assert (got_op, got_status) == (op, status), f"captured {got_op} {got_status}, expected {op} {status}"
        lowered = {k.lower(): v for k, v in headers.items()}
        value = lowered.get("x-amz-crc32")
        assert value is not None, f"{op} {status}: no x-amz-crc32 header among {sorted(lowered)!r}"
        assert value.isdigit(), f"{op} {status}: x-amz-crc32 {value!r} is not an unsigned decimal"
        crc = zlib.crc32(body) & 0xFFFFFFFF
        assert int(value) == crc, (
            f"{op} {status}: x-amz-crc32 {value!r} != crc32 of the {len(body)}-byte body ({crc})"
        )
        return body

    table = ctx.unique_name("sim2real-behav-crc-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    last("CreateTable", 200)

    deadline = time.monotonic() + 300.0
    while ddb.describe_table(TableName=table)["Table"]["TableStatus"] != "ACTIVE":
        assert time.monotonic() < deadline, "the table never reached ACTIVE"
        time.sleep(3)
    last("DescribeTable", 200)

    item = {"pk": {"S": "k1"}, "note": {"S": "Grüße — 東京 \U0001f600"}, "n": {"N": "42"}}
    ddb.put_item(TableName=table, Item=item)
    last("PutItem", 200)
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "k1"}}, ConsistentRead=True)
    body = last("GetItem", 200)
    assert got.get("Item") == item, f"GetItem returned {got.get('Item')!r}"
    assert any(b >= 0x80 for b in body), "the GetItem body carried no multi-byte UTF-8 for the checksum to cover"

    ddb.list_tables(Limit=1)
    last("ListTables", 200)

    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "k1"}}, ConditionExpression="attribute_not_exists(pk)"
    ))
    assert (code, msg) == ("ConditionalCheckFailedException", "The conditional request failed"), (
        f"the conditional put gave {code!r}: {msg!r}"
    )
    last("PutItem", 400)

    missing = ctx.unique_name("sim2real-behav-crc-missing-")
    code, msg = _error(lambda: ddb.describe_table(TableName=missing))
    assert (code, msg) == ("ResourceNotFoundException", f"Requested resource not found: Table: {missing} not found"), (
        f"describing a missing table gave {code!r}: {msg!r}"
    )
    last("DescribeTable", 400)

    code, msg = _error(lambda: ddb.get_item(TableName=table, Key={"pk": {"N": "1"}}))
    assert (code, msg) == ("ValidationException", "The provided key element does not match the schema"), (
        f"a key of the wrong type gave {code!r}: {msg!r}"
    )
    last("GetItem", 400)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
