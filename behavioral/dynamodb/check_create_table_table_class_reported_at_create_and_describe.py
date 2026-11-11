"""create-table-table-class-reported-at-create-and-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-table-table-class-reported-at-create-and-describe"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]


def _wait_active(ddb, table: str) -> None:
    ddb.get_waiter("table_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250}
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TableClass given at CreateTable is reported in CreateTable's own response and in
    DescribeTable; a table created without TableClass omits the block from CreateTable's response.
    """
    ddb = ctx.client("dynamodb")

    classed = ctx.unique_name("sim2real-behav-")
    created = ddb.create_table(
        TableName=classed,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        TableClass="STANDARD_INFREQUENT_ACCESS",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=classed))
    _wait_active(ddb, classed)
    assert created["TableDescription"].get("TableClassSummary") == {
        "TableClass": "STANDARD_INFREQUENT_ACCESS"
    }, (
        f"CreateTable's own response must carry TableClassSummary for the class it was given, "
        f"got {created['TableDescription'].get('TableClassSummary')!r}"
    )

    described = ddb.describe_table(TableName=classed)["Table"]
    assert described.get("TableClassSummary") == {
        "TableClass": "STANDARD_INFREQUENT_ACCESS"
    }, (
        f"DescribeTable must carry the same TableClassSummary, "
        f"got {described.get('TableClassSummary')!r}"
    )

    default = ctx.unique_name("sim2real-behav-")
    created_default = ddb.create_table(
        TableName=default,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=default))
    _wait_active(ddb, default)
    assert "TableClassSummary" not in created_default["TableDescription"], (
        f"a table created with no TableClass must omit TableClassSummary from CreateTable's "
        f"response, got {created_default['TableDescription'].get('TableClassSummary')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
