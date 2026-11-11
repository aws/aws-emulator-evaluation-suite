"""update-table-billing-mode-pay-per-request-no-op-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-table-billing-mode-pay-per-request-no-op-accepted"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]


def _wait_active(ddb, table_name, timeout_s=120.0, interval_s=2.0):
    """Poll DescribeTable until TableStatus is ACTIVE."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        if desc["TableStatus"] == "ACTIVE":
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never settled to ACTIVE in {timeout_s}s (last={desc!r})")


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:data-plane", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdateTable accepts BillingMode=PAY_PER_REQUEST on an already on-demand table as a no-op,
    settles to ACTIVE, and the table keeps serving reads and writes afterward.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-pprnoop-")
    key_schema = [{"AttributeName": "pk", "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": "pk", "AttributeType": "S"}]

    ddb.create_table(
        TableName=table, KeySchema=key_schema, AttributeDefinitions=attr_defs,
        BillingMode="PAY_PER_REQUEST", Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    _wait_active(ddb, table)

    before = ddb.describe_table(TableName=table)["Table"]
    before_mode = before["BillingModeSummary"]["BillingMode"]
    assert before_mode == "PAY_PER_REQUEST", (
        f"expected freshly-created table billing mode PAY_PER_REQUEST, got {before_mode!r}"
    )

    ddb.update_table(TableName=table, BillingMode="PAY_PER_REQUEST")

    after = _wait_active(ddb, table)
    after_mode = after["BillingModeSummary"]["BillingMode"]
    assert after_mode == "PAY_PER_REQUEST", (
        f"expected billing mode to stay PAY_PER_REQUEST after the no-op update, got {after_mode!r}"
    )

    ddb.put_item(TableName=table, Item={"pk": {"S": "k1"}, "v": {"S": "post-noop"}})
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "k1"}}, ConsistentRead=True)["Item"]
    got_v = got["v"]["S"]
    assert got_v == "post-noop", (
        f"expected post-no-op GetItem to read back 'post-noop', got {got_v!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
