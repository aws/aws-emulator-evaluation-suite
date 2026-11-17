"""batch-write-item-size-boundary-missing-table."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-write-item-size-boundary-missing-table"
GROUP = "limits"
SERVICES = ["dynamodb"]
LIMIT_BYTES = 409600


def _attr_name(i: int) -> str:
    """A unique, exactly-27-character attribute name."""
    prefix = f"payload-attr-{i:02d}-"
    name = prefix + "n" * (27 - len(prefix))
    assert len(name) == 27, f"helper built a {len(name)}-char name, expected 27: {name!r}"
    return name


def _item_of_size(pk_value: str, names: list, total_bytes: int) -> dict:
    """An item whose ``pk`` plus every attribute in ``names`` sums to exactly total_bytes."""
    fixed = len("pk".encode()) + len(pk_value.encode()) + sum(len(n.encode()) for n in names)
    payload_bytes = total_bytes - fixed
    n = len(names)
    assert payload_bytes >= n, f"{total_bytes} bytes is too small for {n} named attributes"
    base, extra = divmod(payload_bytes, n)
    item = {"pk": {"S": pk_value}}
    for idx, name in enumerate(names):
        length = base + (extra if idx == 0 else 0)
        item[name] = {"S": "x" * length}
    return item


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteItem naming only a nonexistent table is ResourceNotFoundException for an item
    exactly at the 409600-byte size limit, in a single small attribute, a 27-character-named
    attribute and three attributes, the same shapes BatchWriteItem accepts on a real table.
    """
    ddb = ctx.client("dynamodb")
    real_table = ctx.unique_name("sim2real-behav-bwsz-")
    missing_table = ctx.unique_name("sim2real-behav-bwsz-missing-")
    ddb.create_table(
        TableName=real_table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=real_table))
    ddb.get_waiter("table_exists").wait(TableName=real_table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    shapes = {
        "single": ["data"],
        "long-name": [_attr_name(0)],
        "three-attrs": [_attr_name(0), _attr_name(1), _attr_name(2)],
    }

    for shape_name, names in shapes.items():
        item = _item_of_size(f"missing-{shape_name}", names, LIMIT_BYTES)

        # Positive control: the at-limit item in this shape is accepted whole on the real table,
        # so the rejection below is attributable to the missing table and not to this item's size.
        control = ddb.batch_write_item(RequestItems={real_table: [{"PutRequest": {"Item": item}}]})
        assert control.get("UnprocessedItems", {}) == {}, (
            f"the {shape_name} at-limit item must be fully accepted on the real table, "
            f"got UnprocessedItems={control.get('UnprocessedItems')!r}"
        )
        got = ddb.get_item(TableName=real_table, Key={"pk": {"S": item["pk"]["S"]}}, ConsistentRead=True)
        assert got.get("Item") == item, (
            f"the {shape_name} at-limit item must read back byte-identical, got {got.get('Item')!r}"
        )

        code, message = _error(
            lambda item=item: ddb.batch_write_item(RequestItems={missing_table: [{"PutRequest": {"Item": item}}]})
        )
        assert code == "ResourceNotFoundException", (
            f"BatchWriteItem naming only a nonexistent table with a {shape_name} at-limit item must "
            f"be ResourceNotFoundException, got {code!r}: {message!r}"
        )
        assert message == "Requested resource not found", (
            f"unexpected ResourceNotFoundException message for the {shape_name} shape: {message!r}"
        )

    describe = _error(lambda: ddb.describe_table(TableName=missing_table))
    expected_describe = (
        "ResourceNotFoundException",
        f"Requested resource not found: Table: {missing_table} not found",
    )
    assert describe == expected_describe, (
        f"the nonexistent table must still not exist after the refused calls: expected "
        f"{expected_describe!r}, got {describe!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
