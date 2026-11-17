"""delete-item-write-capacity-billed-on-mixed-number-binary-set-item-size."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-write-capacity-billed-on-mixed-number-binary-set-item-size"
GROUP = "capacity"
SERVICES = ["dynamodb"]

# 37 significant digits, no leading/trailing zeroes, so DynamoDB stores it verbatim and its
# documented size (1 byte per two significant digits, plus one byte) is exact: 1 ("n") + 19 + 1 = 21.
_N_VALUE = "1234567890123456789012345678901234567"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own not-found
    code means it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _item(pk: str, b_len: int) -> dict:
    """"pk"(2)+pk(3)=5, "n"(1)+21 digit-bytes=21, "b"(1)+b_len, "bs"(2)+1-byte element=3."""
    return {
        "pk": {"S": pk},
        "n": {"N": _N_VALUE},
        "b": {"B": b"x" * b_len},
        "bs": {"BS": [b"y"]},
    }


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem's write capacity is billed on the deleted item's total byte size even when that
    size is built from Number and Binary Set members, not only String: an item mixing N, B and BS
    that totals 1024 bytes costs 1 write capacity unit, and one at 1025 bytes costs 2.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-delnbs-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # fixed = pk(5) + n(21) = 26; b(1+994)=995; bs(2+1)=3 -> 26+995+3 = 1024.
    at_boundary = _item("k01", 994)
    ddb.put_item(TableName=table, Item=at_boundary)
    cc_at = ddb.delete_item(
        TableName=table, Key={"pk": {"S": "k01"}}, ReturnConsumedCapacity="TOTAL",
    )["ConsumedCapacity"]
    assert cc_at["CapacityUnits"] == 1.0, (
        f"deleting the 1024-byte mixed N/B/BS item must cost 1.0 write capacity unit, got "
        f"{cc_at['CapacityUnits']!r}"
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "k01"}}, ConsistentRead=True).get("Item") is None, (
        "the deleted 1024-byte item must be gone"
    )

    # one more raw byte in "b" -> 1025 total.
    over_boundary = _item("k02", 995)
    ddb.put_item(TableName=table, Item=over_boundary)
    cc_over = ddb.delete_item(
        TableName=table, Key={"pk": {"S": "k02"}}, ReturnConsumedCapacity="TOTAL",
    )["ConsumedCapacity"]
    assert cc_over["CapacityUnits"] == 2.0, (
        f"deleting the 1025-byte mixed N/B/BS item must cost 2.0 write capacity units, got "
        f"{cc_over['CapacityUnits']!r}"
    )
    assert ddb.get_item(TableName=table, Key={"pk": {"S": "k02"}}, ConsistentRead=True).get("Item") is None, (
        "the deleted 1025-byte item must be gone"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
