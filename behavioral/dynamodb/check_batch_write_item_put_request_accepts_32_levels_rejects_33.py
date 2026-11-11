"""batch-write-item-put-request-accepts-32-levels-rejects-33."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-put-request-accepts-32-levels-rejects-33"
GROUP = "limits"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
_NESTING_MESSAGE = (
    "Nesting Levels have exceeded supported limits: Attributes in the item have nested levels "
    "beyond supported limit"
)
_LEAF = {"S": "leaf"}


def _wrap_maps(levels: int, leaf: dict) -> dict:
    """`levels` nested single-key M wrappers around `leaf`, so the value is `levels` + 1 deep."""
    value = leaf
    for _ in range(levels):
        value = {"M": {"n": value}}
    return value


def _wrap_lists(levels: int, leaf: dict) -> dict:
    """`levels` nested single-element L wrappers around `leaf`."""
    value = leaf
    for _ in range(levels):
        value = {"L": [value]}
    return value


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation",
      "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem's PutRequest accepts a 32-level nested item, map- or list-shaped, with no
    UnprocessedItems, and it reads back intact; a 33-level list-nested item is refused for the
    whole call and nothing lands.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-bwidepth-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # --- 32-level map-nested PutRequest: accepted whole, no UnprocessedItems, lossless read-back ---
    resp = ddb.batch_write_item(RequestItems={t: [
        {"PutRequest": {"Item": {"pk": {"S": "m32"}, "d": _wrap_maps(31, _LEAF)}}},
    ]})
    assert resp.get("UnprocessedItems") == {}, (
        f"a 32-level map-nested PutRequest is within the limit, got UnprocessedItems "
        f"{resp.get('UnprocessedItems')!r}"
    )
    value = ddb.get_item(TableName=t, Key={"pk": {"S": "m32"}}, ConsistentRead=True).get("Item", {}).get("d")
    walked = 0
    while isinstance(value, dict) and "M" in value:
        inner = value["M"]
        assert sorted(inner) == ["n"], (
            f"at wrapper {walked} the stored map must carry exactly the authored key, got {sorted(inner)!r}"
        )
        value = inner["n"]
        walked += 1
    assert walked == 31 and value == _LEAF, (
        f"a 32-level map document written by BatchWriteItem must read back 32 levels deep to the "
        f"unchanged leaf, unwrapped {walked!r} levels before reaching {value!r}"
    )

    # --- 32-level list-nested PutRequest: the positive control for the list-shaped refusal below ---
    resp = ddb.batch_write_item(RequestItems={t: [
        {"PutRequest": {"Item": {"pk": {"S": "l32"}, "d": _wrap_lists(31, _LEAF)}}},
    ]})
    assert resp.get("UnprocessedItems") == {}, (
        f"a 32-level list-nested PutRequest is within the limit, got UnprocessedItems "
        f"{resp.get('UnprocessedItems')!r}"
    )
    value = ddb.get_item(TableName=t, Key={"pk": {"S": "l32"}}, ConsistentRead=True).get("Item", {}).get("d")
    walked = 0
    while isinstance(value, dict) and "L" in value:
        assert len(value["L"]) == 1, (
            f"at wrapper {walked} the stored list must carry exactly the authored element, got "
            f"{len(value['L'])!r} elements"
        )
        value = value["L"][0]
        walked += 1
    assert walked == 31 and value == _LEAF, (
        f"a 32-level list document written by BatchWriteItem must read back 32 levels deep to the "
        f"unchanged leaf, unwrapped {walked!r} levels before reaching {value!r}"
    )

    # --- 33-level list-nested PutRequest alongside a valid sibling: whole call refused, nothing lands ---
    code, message = _error(lambda: ddb.batch_write_item(RequestItems={t: [
        {"PutRequest": {"Item": {"pk": {"S": "ok-sibling"}, "v": {"S": "fine"}}}},
        {"PutRequest": {"Item": {"pk": {"S": "l33"}, "d": _wrap_lists(32, _LEAF)}}},
    ]}))
    assert code == ERR_VALIDATION, (
        f"a BatchWriteItem call with one 33-level list-nested item must be {ERR_VALIDATION} for "
        f"the whole call, got {code!r}: {message!r}"
    )
    assert message == _NESTING_MESSAGE, f"expected the exact ValidationException message, got {message!r}"

    sibling = ddb.get_item(TableName=t, Key={"pk": {"S": "ok-sibling"}}, ConsistentRead=True)
    assert "Item" not in sibling, (
        f"the request is rejected as a whole, so the valid sibling PutRequest must not be "
        f"written, got {sibling.get('Item')!r}"
    )
    deep_item = ddb.get_item(TableName=t, Key={"pk": {"S": "l33"}}, ConsistentRead=True)
    assert "Item" not in deep_item, (
        f"the over-nested list PutRequest must not be written, got {deep_item.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
