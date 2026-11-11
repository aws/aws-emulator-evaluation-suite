"""list-tables-pagination-and-known-table."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tables-pagination-and-known-table"
GROUP = "control-plane"
SERVICES = ["bcm-data-exports"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTables paginates without duplicate/overlapping pages and surfaces COST_AND_USAGE_REPORT."""
    bdx = ctx.client("bcm-data-exports")

    page1 = bdx.list_tables(MaxResults=1)
    assert len(page1["Tables"]) == 1, f"expected 1 table with MaxResults=1, got {len(page1['Tables'])}"
    token = page1.get("NextToken")
    assert token, "expected a NextToken since more than one table exists"

    page2 = bdx.list_tables(MaxResults=1, NextToken=token)
    assert len(page2["Tables"]) == 1, f"expected 1 table with MaxResults=1, got {len(page2['Tables'])}"
    name1, name2 = page1["Tables"][0]["TableName"], page2["Tables"][0]["TableName"]
    assert name2 != name1, f"page 2 repeated page 1's table {name1!r} instead of advancing"

    all_tables = _list_all_tables(bdx)
    names = [t["TableName"] for t in all_tables]
    assert len(names) == len(set(names)), f"duplicate table names across the full pagination: {names}"
    assert "COST_AND_USAGE_REPORT" in names, f"COST_AND_USAGE_REPORT missing from table catalog: {names}"
    cur = next(t for t in all_tables if t["TableName"] == "COST_AND_USAGE_REPORT")
    property_names = {p["Name"] for p in cur.get("TableProperties", [])}
    assert "TIME_GRANULARITY" in property_names, (
        f"COST_AND_USAGE_REPORT TableProperties missing TIME_GRANULARITY: {property_names}"
    )


def _list_all_tables(bdx):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = bdx.list_tables(**kwargs)
        out.extend(resp.get("Tables", []))
        token = resp.get("NextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
