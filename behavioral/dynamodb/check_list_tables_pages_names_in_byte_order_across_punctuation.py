"""list-tables-pages-names-in-byte-order-across-punctuation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tables-pages-names-in-byte-order-across-punctuation"
GROUP = "tables"
SERVICES = ["dynamodb"]

# Name suffixes in UTF-8 byte order ('-' < '.' < 'Z' < '_' < 'b'), unlike locale collation.
_SUFFIXES = ["-a-z", "-a.z", "-aZ", "-a_z", "-ab"]


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


def _walk(ddb, start, prefix, limit):
    """Table names after start that begin with prefix, following LastEvaluatedTableName."""
    names, pages = [], 0
    kwargs = {"ExclusiveStartTableName": start, "Limit": limit}
    while True:
        resp = ddb.list_tables(**kwargs)
        pages += 1
        page = resp["TableNames"]
        assert len(page) <= limit, f"ListTables Limit={limit} returned {len(page)} names: {page!r}"
        assert page == sorted(page), f"ListTables page is not in byte order: {page!r}"
        names.extend(n for n in page if n.startswith(prefix))
        cursor = resp.get("LastEvaluatedTableName")
        if cursor is None or (page and not page[-1].startswith(prefix)):
            return names
        assert pages <= 50, f"ListTables walk from {start!r} did not end after 50 pages: {names!r}"
        kwargs["ExclusiveStartTableName"] = cursor


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTables orders names by UTF-8 bytes where punctuation and case disagree with collation
    (-a-z < -a.z < -aZ < -a_z < -ab); a Limit=1 cursor walk returns each of them once, in that order.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ListTables.html
    """
    ddb = ctx.client("dynamodb")
    prefix = ctx.unique_name("sim2real-behav-ddb-lt-")
    names = [prefix + s for s in _SUFFIXES]
    for name in reversed(names):
        ddb.create_table(
            TableName=name,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        ctx.on_cleanup(_teardown(lambda name=name: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    for name in names:
        _wait_active(ddb, ctx, name)

    walk = _walk(ddb, prefix, prefix, 1)
    assert walk == names, f"ListTables Limit=1 walk listed {walk!r}, expected byte order {names!r}"
    page = _walk(ddb, prefix, prefix, 100)
    assert page == names, f"ListTables Limit=100 from {prefix!r} listed {page!r}, expected {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
