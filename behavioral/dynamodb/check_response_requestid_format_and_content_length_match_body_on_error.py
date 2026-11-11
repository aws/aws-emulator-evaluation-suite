"""response-requestid-format-and-content-length-match-body-on-error."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "response-requestid-format-and-content-length-match-body-on-error"
GROUP = "wire-integrity"
SERVICES = ["dynamodb"]

_REQUEST_ID_RE = re.compile(r"^[0-9A-Z]{52}$")
_CONDITIONAL_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A refused DynamoDB response carries the same x-amzn-RequestId format and an exact
    Content-Length as a successful one; its error code and message never move.
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
        request_id = lowered.get("x-amzn-requestid")
        assert request_id is not None, f"{op} {status}: no x-amzn-requestid header among {sorted(lowered)!r}"
        assert _REQUEST_ID_RE.match(request_id), (
            f"{op} {status}: x-amzn-requestid {request_id!r} does not match {_REQUEST_ID_RE.pattern!r}"
        )
        content_length = lowered.get("content-length")
        assert content_length is not None, f"{op} {status}: no content-length header among {sorted(lowered)!r}"
        assert content_length.isdigit(), f"{op} {status}: content-length {content_length!r} is not an unsigned decimal"
        assert int(content_length) == len(body), (
            f"{op} {status}: content-length {content_length!r} != literal body length {len(body)}"
        )
        return body

    # Positive control: DescribeTable on a table that exists answers 200 with the same header
    # shape the refusals below are held to.
    table = ctx.unique_name("sim2real-behav-reqid-err-")
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

    item = {"pk": {"S": "k1"}}
    ddb.put_item(TableName=table, Item=item)
    last("PutItem", 200)

    # Negative 1: a conditional write that fails leaves the item unchanged, proven by a read.
    code, msg = _error(lambda: ddb.put_item(
        TableName=table, Item={"pk": {"S": "k1"}, "note": {"S": "clobber"}},
        ConditionExpression="attribute_not_exists(pk)",
    ))
    assert (code, msg) == _CONDITIONAL_FAILED, f"the conditional put gave {code!r}: {msg!r}"
    last("PutItem", 400)

    got = ddb.get_item(TableName=table, Key={"pk": {"S": "k1"}}, ConsistentRead=True)
    last("GetItem", 200)
    assert got.get("Item") == item, f"the failed conditional write mutated the item to {got.get('Item')!r}"

    # Negative 2: describing a table that was never created.
    missing = ctx.unique_name("sim2real-behav-reqid-missing-")
    code, msg = _error(lambda: ddb.describe_table(TableName=missing))
    assert (code, msg) == (
        "ResourceNotFoundException", f"Requested resource not found: Table: {missing} not found"
    ), f"describing a missing table gave {code!r}: {msg!r}"
    last("DescribeTable", 400)

    # Negative 3: a key whose attribute type does not match the table's schema.
    code, msg = _error(lambda: ddb.get_item(TableName=table, Key={"pk": {"N": "1"}}))
    assert (code, msg) == (
        "ValidationException", "The provided key element does not match the schema"
    ), f"a key of the wrong type gave {code!r}: {msg!r}"
    last("GetItem", 400)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
