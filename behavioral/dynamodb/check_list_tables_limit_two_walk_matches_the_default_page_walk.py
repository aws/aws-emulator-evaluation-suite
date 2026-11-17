"""list-tables-limit-two-walk-matches-the-default-page-walk."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tables-limit-two-walk-matches-the-default-page-walk"
GROUP = "pagination"
SERVICES = ["dynamodb"]

_TABLES = 5
_PAGE = 2
_PAGE_CAP = 5000  # a walk that never drops LastEvaluatedTableName fails instead of spinning


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_active(ctx, ddb, name: str) -> None:
    """DescribeTable polled until the table is ACTIVE."""
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
    while True:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended before table {name} became ACTIVE")
            raise AssertionError(f"table {name} is still {status!r}, not ACTIVE")
        time.sleep(2)


def _delete_table(ddb, name: str):
    """A cleanup deleting the table; a table still being created is retried until it can be deleted."""

    def run_undo():
        deadline = time.monotonic() + 240.0
        while True:
            try:
                ddb.delete_table(TableName=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return run_undo


def _walk(ddb, limit: int | None) -> list[list[str]]:
    """Every ListTables page in order, following LastEvaluatedTableName until a page carries none."""
    pages: list[list[str]] = []
    kwargs = {} if limit is None else {"Limit": limit}
    while True:
        resp = ddb.list_tables(**kwargs)
        pages.append(list(resp.get("TableNames", [])))
        cursor = resp.get("LastEvaluatedTableName")
        if not cursor:
            return pages
        assert len(pages) < _PAGE_CAP, f"ListTables still returned a cursor after {len(pages)} pages"
        kwargs["ExclusiveStartTableName"] = cursor


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTables walked at Limit=2 to its last page lists the check's tables once each, exactly as
    the walk at the default page size lists them.
    """
    ddb = ctx.client("dynamodb")
    stem = ctx.unique_name("sim2real-ltpw-")
    own = sorted(f"{stem}-{i}" for i in range(_TABLES))
    for name in own:
        ddb.create_table(
            TableName=name,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        ctx.on_cleanup(_delete_table(ddb, name))
    for name in own:
        _wait_active(ctx, ddb, name)

    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        whole = [n for page in _walk(ddb, None) for n in page if n in own]
        small = _walk(ddb, _PAGE)
        paged = [n for page in small for n in page if n in own]
        if sorted(whole) == own and sorted(paged) == own:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended before both ListTables walks listed the tables")
            break
        time.sleep(2)

    assert sorted(whole) == own, f"the default-page walk listed {sorted(whole)!r}, expected {own!r}"
    sizes = [len(page) for page in small]
    assert all(size <= _PAGE for size in sizes), f"a Limit={_PAGE} page held more: page sizes {sizes!r}"
    assert len(paged) == len(set(paged)), f"the Limit={_PAGE} walk listed a table twice: {paged!r}"
    assert sorted(paged) == sorted(whole), (
        f"the Limit={_PAGE} walk listed {sorted(paged)!r}, the default-page walk {sorted(whole)!r}"
    )
    assert len(small) >= 3, f"{_TABLES} tables at Limit={_PAGE} gave only {len(small)} page(s)"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
