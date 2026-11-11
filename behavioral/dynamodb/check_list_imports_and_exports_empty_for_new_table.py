"""list-imports-and-exports-empty-for-new-table."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-imports-and-exports-empty-for-new-table"
GROUP = 'limits'
SERVICES = ['dynamodb']


def _wait_for_table_active(ddb, table_name, timeout_s=90.0, interval_s=1.0):
    """Poll DescribeTable until ACTIVE. CreateTable is eventually consistent, so a
    transient ResourceNotFoundException counts as "not yet", never a failure."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            status = "PENDING"
        if status == "ACTIVE":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never went ACTIVE in {timeout_s}s (last={status})")


def _create_simple_table(ddb, ctx):
    """Create a pk (S) + sk (S) composite-key table, register teardown, wait ACTIVE."""
    table_name = ctx.unique_name("sim2real-behav-ddb-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)
    return table_name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created table has no import or export jobs associated with it."""
    ddb = ctx.client("dynamodb")
    table_name = _create_simple_table(ddb, ctx)
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]

    imports = ddb.list_imports(TableArn=table_arn)
    import_list = imports.get("ImportSummaryList", [])
    assert import_list == [], f"expected no import jobs for a new table, got {import_list}"

    exports = ddb.list_exports(TableArn=table_arn)
    export_list = exports.get("ExportSummaries", [])
    assert export_list == [], f"expected no export jobs for a new table, got {export_list}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
