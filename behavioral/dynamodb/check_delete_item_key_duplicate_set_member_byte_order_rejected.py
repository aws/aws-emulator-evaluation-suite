"""delete-item-key-duplicate-set-member-byte-order-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-key-duplicate-set-member-byte-order-rejected"
GROUP = "representation"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A duplicate member in a DeleteItem Key's BS is refused ValidationException naming the
    distinct members seen so far in ascending byte order before the duplicate, with the
    duplicate appended; the same refusal for NS names no members at all.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-delkey-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "control"}, "note": {"S": "kept"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "victim"}, "note": {"S": "to-delete"}})

    # positive control: an ordinary DeleteItem with a scalar key succeeds and removes exactly it
    ddb.delete_item(TableName=t, Key={"pk": {"S": "victim"}})
    got = ddb.get_item(TableName=t, Key={"pk": {"S": "victim"}}, ConsistentRead=True)
    assert "Item" not in got, f"DeleteItem with a valid scalar key must remove the item, got {got!r}"

    invalid = "1 validation error detected: One or more parameter values were invalid: "
    _BS_DUP = (
        ERR_VALIDATION,
        invalid + 'Input collection ["AQ==","eg==","AQ=="]of type BS contains duplicates.',
    )
    _NS_DUP = (ERR_VALIDATION, invalid + "Input collection contains duplicates.")

    # a DeleteItem Key whose BS has a duplicate: the two distinct members seen before the
    # duplicate (0x7a, 0x01) are named in ascending byte order (0x01 then 0x7a), and the
    # duplicate (0x01) is appended last -- not the order the request gave them in.
    expect_error(
        lambda: ddb.delete_item(TableName=t, Key={"pk": {"BS": [b"\x7a", b"\x01", b"\x01"]}}),
        *_BS_DUP,
    )

    # the same shape on NS: AWS refuses it the same way but names no members at all.
    expect_error(
        lambda: ddb.delete_item(TableName=t, Key={"pk": {"NS": ["50", "3", "7", "3"]}}),
        *_NS_DUP,
    )

    got = ddb.get_item(TableName=t, Key={"pk": {"S": "control"}}, ConsistentRead=True).get("Item")
    assert got == {"pk": {"S": "control"}, "note": {"S": "kept"}}, (
        f"the control item must be untouched by the rejected DeleteItem calls, got {got!r}"
    )
    scanned = ddb.scan(TableName=t, ConsistentRead=True, Select="COUNT")
    assert scanned["Count"] == 1, (
        f"only the control item may remain after the victim's delete and the two rejected "
        f"DeleteItem calls, got {scanned['Count']!r} items"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
