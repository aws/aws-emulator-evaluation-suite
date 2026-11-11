"""on-demand-throughput-round-trips-at-create-then-update-changes-both-ceilings."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "on-demand-throughput-round-trips-at-create-then-update-changes-both-ceilings"
GROUP = "table_lifecycle"
SERVICES = ["dynamodb"]


def _wait_active(ddb, table, deadline_s=240):
    """Poll DescribeTable until the table is ACTIVE."""
    end = time.time() + deadline_s
    while time.time() < end:
        t = ddb.describe_table(TableName=table)["Table"]
        if t["TableStatus"] == "ACTIVE":
            return t
        time.sleep(3)
    raise AssertionError(f"{table} never settled to ACTIVE within {deadline_s}s")


def _delete_table(ddb, table, timeout_s=300):
    """Teardown: DeleteTable is refused while the last throughput update is still settling;
    retry to a deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OnDemandThroughput given at CreateTable is described back unchanged, and UpdateTable
    changing both MaxReadRequestUnits and MaxWriteRequestUnits replaces the pair as described."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        OnDemandThroughput={"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 5},
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    t = _wait_active(ddb, table)
    assert t["OnDemandThroughput"] == {"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 5}, (
        f"CreateTable's OnDemandThroughput was {{'MaxReadRequestUnits': 10, "
        f"'MaxWriteRequestUnits': 5}}, DescribeTable returned {t.get('OnDemandThroughput')!r}"
    )

    ddb.update_table(
        TableName=table,
        OnDemandThroughput={"MaxReadRequestUnits": 20, "MaxWriteRequestUnits": 15},
    )
    t = _wait_active(ddb, table)
    assert t["OnDemandThroughput"] == {"MaxReadRequestUnits": 20, "MaxWriteRequestUnits": 15}, (
        f"UpdateTable set OnDemandThroughput to {{'MaxReadRequestUnits': 20, "
        f"'MaxWriteRequestUnits': 15}}, DescribeTable returned {t.get('OnDemandThroughput')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
