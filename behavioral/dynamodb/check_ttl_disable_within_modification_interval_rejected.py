"""ttl-disable-within-modification-interval-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ttl-disable-within-modification-interval-rejected"
GROUP = "ttl"
SERVICES = ["dynamodb"]

ATTR = "expires_at"


def _error(fn) -> tuple:
    """The (code, message) fn raised; a call that unexpectedly succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ttl(ddb, name: str) -> dict:
    return ddb.describe_time_to_live(TableName=name)["TimeToLiveDescription"]


def _poll_ttl(ddb, name: str, status: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = _ttl(ddb, name)
    while last.get("TimeToLiveStatus") != status and time.monotonic() < deadline:
        time.sleep(3.0)
        last = _ttl(ddb, name)
    return last


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Disabling TTL right after enabling it is refused with ValidationException and TTL stays
    ENABLED, because DynamoDB allows one TTL modification per interval; the enable is accepted.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ttlint-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 90})

    before = _ttl(ddb, table)
    assert before.get("TimeToLiveStatus") == "DISABLED", (
        f"a new table must start with TTL DISABLED; got {before!r}"
    )

    enabled = ddb.update_time_to_live(
        TableName=table, TimeToLiveSpecification={"Enabled": True, "AttributeName": ATTR},
    )["TimeToLiveSpecification"]
    assert enabled == {"Enabled": True, "AttributeName": ATTR}, (
        f"the first TTL modification must be accepted and echoed; got {enabled!r}"
    )
    live = _poll_ttl(ddb, table, "ENABLED")
    assert (live.get("TimeToLiveStatus"), live.get("AttributeName")) == ("ENABLED", ATTR), (
        f"TTL must reach ENABLED on {ATTR!r}; got {live!r}"
    )

    code, message = _error(lambda: ddb.update_time_to_live(
        TableName=table, TimeToLiveSpecification={"Enabled": False, "AttributeName": ATTR},
    ))
    assert code == "ValidationException", (
        f"disabling TTL moments after enabling it must be rejected with ValidationException; got "
        f"{code!r}"
    )
    expected = "Time to live has been modified multiple times within a fixed interval"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = _ttl(ddb, table)
    assert (after.get("TimeToLiveStatus"), after.get("AttributeName")) == ("ENABLED", ATTR), (
        f"a rejected disable must leave TTL ENABLED on {ATTR!r}; DescribeTimeToLive says {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
