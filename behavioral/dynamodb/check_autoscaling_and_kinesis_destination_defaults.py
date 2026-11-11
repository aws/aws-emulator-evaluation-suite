"""autoscaling-and-kinesis-destination-defaults."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "autoscaling-and-kinesis-destination-defaults"
GROUP = 'limits'
SERVICES = ['dynamodb']


def _error(fn):
    """The (Code, Message) of a call real AWS refuses. RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_for_table_active(ddb, table_name)
    return table_name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTableReplicaAutoScaling rejects a non-replicated table, and a fresh table has zero Kinesis destinations."""
    ddb = ctx.client("dynamodb")
    table_name = _create_simple_table(ddb, ctx)

    # Real DynamoDB treats replica auto-scaling as a global-table-only concept: a plain
    # single-region table is reported as a non-existent global table.
    def describe_autoscaling():
        return ddb.describe_table_replica_auto_scaling(TableName=table_name)

    code, message = _error(describe_autoscaling)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for replica auto-scaling on a "
        f"non-replicated table, got {code}"
    )
    expected_msg = f"Global table with name: '{table_name}' does not exist."
    assert message == expected_msg, f"expected {expected_msg!r}, got {message!r}"

    kds = ddb.describe_kinesis_streaming_destination(TableName=table_name)
    assert kds["TableName"] == table_name, (
        f"expected TableName {table_name!r} echoed back, got {kds.get('TableName')!r}"
    )
    assert kds["KinesisDataStreamDestinations"] == [], (
        f"expected no Kinesis destinations on a fresh table, got "
        f"{kds['KinesisDataStreamDestinations']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
