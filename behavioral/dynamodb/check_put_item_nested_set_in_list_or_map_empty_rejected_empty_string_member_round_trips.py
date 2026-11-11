"""put-item-nested-set-in-list-or-map-empty-rejected-empty-string-member-round-trips."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-item-nested-set-in-list-or-map-empty-rejected-empty-string-member-round-trips"
GROUP = "representation"
SERVICES = ["dynamodb"]

_INVALID = "1 validation error detected: One or more parameter values were invalid: "
_SS_EMPTY = ("ValidationException", _INVALID + "An string set  may not be empty")
_NS_EMPTY = ("ValidationException", _INVALID + "An number set  may not be empty")
_BS_EMPTY = ("ValidationException", _INVALID + "Binary sets should not be empty")


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


def _item(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:representation", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem refuses an empty SS, NS or BS nested inside an L element or an M value with the
    type's empty-set ValidationException, and stores nothing at that key; a set
    holding an empty-string member nested the same way is accepted and round-trips intact.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddb-nestset-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # An empty set nested inside an L element is refused with the type's empty-set message.
    empty_in_list = {
        "ss-in-list": ("L", {"SS": []}, _SS_EMPTY),
        "ns-in-list": ("L", {"NS": []}, _NS_EMPTY),
        "bs-in-list": ("L", {"BS": []}, _BS_EMPTY),
    }
    for pk, (container, member, (code, message)) in empty_in_list.items():
        item = {"pk": {"S": pk}, "attr": {container: [member]}}
        expect_error(lambda item=item: ddb.put_item(TableName=t, Item=item), code, message)
        assert _item(ddb, t, pk) is None, f"a rejected empty set nested in an L must not be stored, pk={pk!r}"

    # An empty set nested inside an M value is refused the same way.
    empty_in_map = {
        "ss-in-map": ("SS", [], _SS_EMPTY),
        "ns-in-map": ("NS", [], _NS_EMPTY),
        "bs-in-map": ("BS", [], _BS_EMPTY),
    }
    for pk, (kind, members, (code, message)) in empty_in_map.items():
        item = {"pk": {"S": pk}, "attr": {"M": {"s": {kind: members}}}}
        expect_error(lambda item=item: ddb.put_item(TableName=t, Item=item), code, message)
        assert _item(ddb, t, pk) is None, f"a rejected empty set nested in an M must not be stored, pk={pk!r}"

    # A set holding an empty-string member, nested the same two ways, is legal and round-trips.
    ddb.put_item(TableName=t, Item={"pk": {"S": "ss-emptymember-in-list"}, "attr": {"L": [{"SS": ["", "x"]}]}})
    got = _item(ddb, t, "ss-emptymember-in-list")
    assert got is not None, "an SS with an empty-string member nested in an L must be stored"
    members = got["attr"]["L"][0]["SS"]
    assert sorted(members) == ["", "x"], (
        f"an SS with an empty-string member nested in an L must round-trip both members, got {members!r}"
    )

    ddb.put_item(TableName=t, Item={"pk": {"S": "ss-emptymember-in-map"}, "attr": {"M": {"s": {"SS": ["", "x"]}}}})
    got = _item(ddb, t, "ss-emptymember-in-map")
    assert got is not None, "an SS with an empty-string member nested in an M must be stored"
    members = got["attr"]["M"]["s"]["SS"]
    assert sorted(members) == ["", "x"], (
        f"an SS with an empty-string member nested in an M must round-trip both members, got {members!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
