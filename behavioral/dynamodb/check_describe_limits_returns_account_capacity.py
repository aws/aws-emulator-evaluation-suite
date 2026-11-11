"""describe-limits-returns-account-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-limits-returns-account-capacity"
GROUP = "server-side"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLimits is a server-enforced, account-scoped read: it returns
    positive account-level throughput ceilings, and the per-table ceilings
    never exceed the account-level ceilings, on every call."""
    ddb = ctx.client("dynamodb")

    limits = ddb.describe_limits()
    account_read = limits["AccountMaxReadCapacityUnits"]
    account_write = limits["AccountMaxWriteCapacityUnits"]
    table_read = limits["TableMaxReadCapacityUnits"]
    table_write = limits["TableMaxWriteCapacityUnits"]

    for value in (account_read, account_write, table_read, table_write):
        assert isinstance(value, int) and value > 0, f"expected a positive integer limit, got {value!r}"

    assert table_read <= account_read, "a single table's read limit exceeded the account-wide read limit"
    assert table_write <= account_write, "a single table's write limit exceeded the account-wide write limit"

    # Server-enforced account limits are stable across back-to-back calls.
    limits_again = ddb.describe_limits()
    assert limits_again["AccountMaxReadCapacityUnits"] == account_read, (
        f"AccountMaxReadCapacityUnits changed between calls: {account_read!r} -> "
        f"{limits_again['AccountMaxReadCapacityUnits']!r}"
    )
    assert limits_again["AccountMaxWriteCapacityUnits"] == account_write, (
        f"AccountMaxWriteCapacityUnits changed between calls: {account_write!r} -> "
        f"{limits_again['AccountMaxWriteCapacityUnits']!r}"
    )
    assert limits_again["TableMaxReadCapacityUnits"] == table_read, (
        f"TableMaxReadCapacityUnits changed between calls: {table_read!r} -> "
        f"{limits_again['TableMaxReadCapacityUnits']!r}"
    )
    assert limits_again["TableMaxWriteCapacityUnits"] == table_write, (
        f"TableMaxWriteCapacityUnits changed between calls: {table_write!r} -> "
        f"{limits_again['TableMaxWriteCapacityUnits']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
