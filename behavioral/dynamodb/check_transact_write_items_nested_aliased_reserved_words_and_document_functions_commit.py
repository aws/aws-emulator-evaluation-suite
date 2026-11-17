"""transact-write-items-nested-aliased-reserved-words-and-document-functions-commit."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-nested-aliased-reserved-words-and-document-functions-commit"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_CANCELED = "TransactionCanceledException"
_CONDITION_FAILED = "ConditionalCheckFailed"


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
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _get(ddb, table, key):
    """The item at key read with ConsistentRead, or None."""
    return ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")


def _error(fn):
    """(Error.Code, Error.Message, CancellationReasons) of the ClientError fn() raises.

    An unexpected success fails, quoting the result.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message"), exc.response.get("CancellationReasons")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems whose ConditionCheck, Put, Delete and Update actions alias reserved
    words on nested map/list paths and call functions over them commits and applies every action.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ReservedWords.html
    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-tw-nest-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    cc_key = {"pk": {"S": "cc"}}
    cc_item = {**cc_key, "m": {"M": {"status": {"S": "active"}, "name": {"S": "alpha-widget-beta"}}}}
    put_key = {"pk": {"S": "put"}}
    put_old = {**put_key, "m": {"M": {"name": {"S": "beta-item"}}}}
    del_key = {"pk": {"S": "del"}}
    del_item = {**del_key, "l": {"L": [{"M": {"status": {"S": "done"}}}, {"S": "tail"}]}}
    upd_key = {"pk": {"S": "upd"}}
    upd_old = {**upd_key, "m": {"M": {"tags": {"L": [{"S": "a"}, {"S": "b"}]}, "year": {"N": "2020"}}}}
    for item in (cc_item, put_old, del_item, upd_old):
        ddb.put_item(TableName=table, Item=item)

    put_new = {**put_key, "m": {"M": {"name": {"S": "gamma-item"}}}, "seq": {"N": "1"}}

    ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": cc_key,
            "ConditionExpression": "attribute_exists(#m.#status) AND #m.#status = :active "
                                    "AND contains(#m.#name, :needle)",
            "ExpressionAttributeNames": {"#m": "m", "#status": "status", "#name": "name"},
            "ExpressionAttributeValues": {":active": {"S": "active"}, ":needle": {"S": "widget"}},
        }},
        {"Put": {
            "TableName": table, "Item": put_new,
            "ConditionExpression": "attribute_type(#m.#name, :s) AND begins_with(#m.#name, :b)",
            "ExpressionAttributeNames": {"#m": "m", "#name": "name"},
            "ExpressionAttributeValues": {":s": {"S": "S"}, ":b": {"S": "beta"}},
        }},
        {"Delete": {
            "TableName": table, "Key": del_key,
            "ConditionExpression": "#l[0].#status = :done AND attribute_not_exists(#l[0].#missing)",
            "ExpressionAttributeNames": {"#l": "l", "#status": "status", "#missing": "missing"},
            "ExpressionAttributeValues": {":done": {"S": "done"}},
        }},
        {"Update": {
            "TableName": table, "Key": upd_key,
            "UpdateExpression": "SET #m.#year = :newyear",
            "ConditionExpression": "size(#m.#tags) = :two AND #m.#year = :oldyear",
            "ExpressionAttributeNames": {"#m": "m", "#year": "year", "#tags": "tags"},
            "ExpressionAttributeValues": {
                ":two": {"N": "2"}, ":oldyear": {"N": "2020"}, ":newyear": {"N": "2021"},
            },
        }},
    ])

    got_cc = _get(ddb, table, cc_key)
    assert got_cc == cc_item, f"the ConditionCheck action must not alter its item, got {got_cc!r}"
    got_put = _get(ddb, table, put_key)
    assert got_put == put_new, f"the committed Put must store {put_new!r}, got {got_put!r}"
    got_del = _get(ddb, table, del_key)
    assert got_del is None, f"the committed Delete must remove the item, got {got_del!r}"
    got_upd = _get(ddb, table, upd_key)
    want_upd = {**upd_key, "m": {"M": {"tags": {"L": [{"S": "a"}, {"S": "b"}]}, "year": {"N": "2021"}}}}
    assert got_upd == want_upd, f"the committed Update must store {want_upd!r}, got {got_upd!r}"

    # Negative control: the same nested-aliased ConditionCheck with a mismatching value must
    # cancel the whole transaction, proving the condition is actually evaluated.
    side_key = {"pk": {"S": "side"}}
    code, msg, reasons = _error(lambda: ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": cc_key,
            "ConditionExpression": "#m.#status = :wrong",
            "ExpressionAttributeNames": {"#m": "m", "#status": "status"},
            "ExpressionAttributeValues": {":wrong": {"S": "inactive"}},
        }},
        {"Put": {"TableName": table, "Item": {**side_key, "v": {"S": "1"}}}},
    ]))
    expected_msg = ("Transaction cancelled, please refer cancellation reasons for specific reasons "
                     f"[{_CONDITION_FAILED}, None]")
    assert (code, msg) == (_CANCELED, expected_msg), f"the mismatching nested condition gave {code!r}: {msg!r}"
    assert reasons == [{"Code": _CONDITION_FAILED, "Message": "The conditional request failed"},
                        {"Code": "None"}], f"unexpected cancellation reasons {reasons!r}"
    assert _get(ddb, table, side_key) is None, "the canceled transaction must not have created the side item"
    assert _get(ddb, table, cc_key) == cc_item, "the canceled transaction must not have altered the cc item"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
