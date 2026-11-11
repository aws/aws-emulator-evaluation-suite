"""update-table-throughput-on-on-demand-table-and-zero-capacity-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-table-throughput-on-on-demand-table-and-zero-capacity-rejected"
GROUP = "tables"
SERVICES = ["dynamodb"]

_WITH_BILLING_MODE_MESSAGE = (
    "One or more parameter values were invalid: ProvisionedThroughput cannot be specified "
    "when BillingMode is PAY_PER_REQUEST"
)
_WITHOUT_BILLING_MODE_MESSAGE = (
    "One or more parameter values were invalid: Neither ReadCapacityUnits nor WriteCapacityUnits "
    "can be specified when BillingMode is PAY_PER_REQUEST"
)
_ZERO_READ_MESSAGE = (
    "1 validation error detected: Value '0' at 'provisionedThroughput.readCapacityUnits' "
    "failed to satisfy constraint: Member must have value greater than or equal to 1"
)


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _capacity(desc):
    pt = desc.get("ProvisionedThroughput", {})
    return pt.get("ReadCapacityUnits"), pt.get("WriteCapacityUnits")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTable refuses throughput on an on-demand table, with or without BillingMode, and a zero
    ReadCapacityUnits on a provisioned one; neither table changes, and a valid capacity change applies.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTable.html
    """
    ddb = ctx.client("dynamodb")
    lax = ctx.client("dynamodb", config=Config(parameter_validation=False))
    base = ctx.unique_name("sim2real-behav-ddb-cap-")
    keys = {
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
    }
    on_demand = f"{base}-od"
    provisioned = f"{base}-pv"
    ddb.create_table(TableName=on_demand, BillingMode="PAY_PER_REQUEST", **keys)
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=on_demand), "ResourceNotFoundException"))
    ddb.create_table(
        TableName=provisioned, BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}, **keys,
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=provisioned), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, on_demand)
    _wait_active(ddb, ctx, provisioned)

    five = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    code, msg = _error(lambda: ddb.update_table(
        TableName=on_demand, BillingMode="PAY_PER_REQUEST", ProvisionedThroughput=five))
    assert (code, msg) == ("ValidationException", _WITH_BILLING_MODE_MESSAGE), (
        f"BillingMode PAY_PER_REQUEST plus throughput on an on-demand table gave {code!r}: {msg!r}"
    )
    code, msg = _error(lambda: ddb.update_table(TableName=on_demand, ProvisionedThroughput=five))
    assert (code, msg) == ("ValidationException", _WITHOUT_BILLING_MODE_MESSAGE), (
        f"throughput alone on an on-demand table gave {code!r}: {msg!r}"
    )
    desc = _wait_active(ddb, ctx, on_demand)
    mode = desc.get("BillingModeSummary", {}).get("BillingMode")
    assert mode == "PAY_PER_REQUEST", f"after the refusals the on-demand table bills as {mode!r}"
    assert _capacity(desc) == (0, 0), f"after the refusals the on-demand table reports {_capacity(desc)!r}"

    code, msg = _error(lambda: lax.update_table(
        TableName=provisioned, ProvisionedThroughput={"ReadCapacityUnits": 0, "WriteCapacityUnits": 1}))
    assert (code, msg) == ("ValidationException", _ZERO_READ_MESSAGE), (
        f"ReadCapacityUnits=0 on a provisioned table gave {code!r}: {msg!r}"
    )
    desc = _wait_active(ddb, ctx, provisioned)
    assert _capacity(desc) == (1, 1), f"after the refused zero the provisioned table reports {_capacity(desc)!r}"

    ddb.update_table(TableName=provisioned, ProvisionedThroughput={"ReadCapacityUnits": 2, "WriteCapacityUnits": 1})
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    while True:
        desc = _wait_active(ddb, ctx, provisioned)
        if _capacity(desc) == (2, 1) or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert _capacity(desc) == (2, 1), f"a valid capacity change left the table at {_capacity(desc)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
