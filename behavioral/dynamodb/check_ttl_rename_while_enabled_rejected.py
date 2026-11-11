"""ttl-rename-while-enabled-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ttl-rename-while-enabled-rejected"
GROUP = "ttl"
SERVICES = ["dynamodb"]

ATTR_LIVE = "expires_at"
ATTR_OTHER = "purge_after"


def _error(fn) -> tuple:
    """The (code, message) fn raised; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _make_table(ctx, ddb, prefix: str) -> str:
    name = ctx.unique_name(prefix)
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _ttl(ddb, name: str) -> dict:
    return ddb.describe_time_to_live(TableName=name)["TimeToLiveDescription"]


def _poll_ttl(ddb, name: str, status: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = _ttl(ddb, name)
    while last.get("TimeToLiveStatus") != status and time.monotonic() < deadline:
        time.sleep(3.0)
        last = _ttl(ddb, name)
    return last


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once TTL is ENABLED on one attribute, enabling it on a different attribute is refused with
    ValidationException and the live TTL is untouched; a table without TTL accepts that attribute.
    """
    ddb = ctx.client("dynamodb")

    # --- set up: TTL live on ATTR_LIVE ----------------------------------------------------------
    table = _make_table(ctx, ddb, "sim2real-behav-ttlren-")
    enabled = ddb.update_time_to_live(
        TableName=table, TimeToLiveSpecification={"Enabled": True, "AttributeName": ATTR_LIVE},
    )["TimeToLiveSpecification"]
    assert enabled == {"Enabled": True, "AttributeName": ATTR_LIVE}, (
        f"UpdateTimeToLive must echo the enabled specification; got {enabled!r}"
    )
    live = _poll_ttl(ddb, table, "ENABLED")
    assert (live.get("TimeToLiveStatus"), live.get("AttributeName")) == ("ENABLED", ATTR_LIVE), (
        f"TTL must reach ENABLED on {ATTR_LIVE!r} before the rename is attempted; got {live!r}"
    )

    # --- break exactly one thing: point the enabled TTL at a different attribute ----------------
    code, message = _error(lambda: ddb.update_time_to_live(
        TableName=table, TimeToLiveSpecification={"Enabled": True, "AttributeName": ATTR_OTHER},
    ))
    assert code == "ValidationException", (
        f"enabling TTL on {ATTR_OTHER!r} while it is active on {ATTR_LIVE!r} must be rejected with "
        f"ValidationException; got {code!r}"
    )
    expected = f"TimeToLive is active on a different AttributeName: current AttributeName is {ATTR_LIVE}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- effect absent: TTL is still bound to the original attribute ----------------------------
    after = _ttl(ddb, table)
    assert (after.get("TimeToLiveStatus"), after.get("AttributeName")) == ("ENABLED", ATTR_LIVE), (
        f"a rejected rename must leave TTL ENABLED on {ATTR_LIVE!r}; DescribeTimeToLive says {after!r}"
    )

    # --- positive control: the rejected attribute name is itself valid --------------------------
    control = _make_table(ctx, ddb, "sim2real-behav-ttlctl-")
    ok = ddb.update_time_to_live(
        TableName=control, TimeToLiveSpecification={"Enabled": True, "AttributeName": ATTR_OTHER},
    )["TimeToLiveSpecification"]
    assert ok == {"Enabled": True, "AttributeName": ATTR_OTHER}, (
        f"a table with no TTL yet must accept {ATTR_OTHER!r}; UpdateTimeToLive echoed {ok!r}"
    )
    ctl = _poll_ttl(ddb, control, "ENABLED")
    assert (ctl.get("TimeToLiveStatus"), ctl.get("AttributeName")) == ("ENABLED", ATTR_OTHER), (
        f"the control table's TTL must reach ENABLED on {ATTR_OTHER!r}; got {ctl!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
