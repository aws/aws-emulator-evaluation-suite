"""consumed-capacity-binary-attribute-counts-raw-bytes-not-base64."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "consumed-capacity-binary-attribute-counts-raw-bytes-not-base64"
GROUP = "expressions"
SERVICES = ["dynamodb"]


def _item(pk: str, raw_len: int) -> dict:
    """A 3-byte key plus one Binary attribute of `raw_len` raw bytes."""
    return {"pk": {"S": pk}, "b": {"B": b"x" * raw_len}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItem's write capacity for a Binary attribute is billed on its raw byte length: an item
    totalling exactly 1024 raw bytes costs 1 write capacity unit and 1025 costs 2, even though the
    attribute's base64 text is already longer than 1024 characters in both cases.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # "pk" (2) + a 3-char key value + "b" (1) + raw_len = raw_len + 6; raw_len=1018 -> 1024 total.
    at_boundary = _item("k01", 1018)
    base64_at_boundary = len(base64.b64encode(at_boundary["b"]["B"]))
    cc_at = ddb.put_item(TableName=table, Item=at_boundary, ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]
    assert cc_at["CapacityUnits"] == 1.0, (
        f"a 1024-raw-byte item (base64 {base64_at_boundary} chars) cost {cc_at['CapacityUnits']!r} "
        f"write capacity units, expected 1.0"
    )

    over_boundary = _item("k02", 1019)
    cc_over = ddb.put_item(TableName=table, Item=over_boundary, ReturnConsumedCapacity="TOTAL")["ConsumedCapacity"]
    assert cc_over["CapacityUnits"] == 2.0, (
        f"a 1025-raw-byte item cost {cc_over['CapacityUnits']!r} write capacity units, expected 2.0"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
