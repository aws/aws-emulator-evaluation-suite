"""get-table-schema-known-columns."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-table-schema-known-columns"
GROUP = "control-plane"
SERVICES = ["bcm-data-exports"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTable for COST_AND_USAGE_REPORT returns the documented schema columns."""
    bdx = ctx.client("bcm-data-exports")
    resp = bdx.get_table(TableName="COST_AND_USAGE_REPORT")
    assert resp["TableName"] == "COST_AND_USAGE_REPORT"
    column_names = {c["Name"] for c in resp["Schema"]}
    assert "identity_line_item_id" in column_names
    assert "line_item_unblended_cost" in column_names
    assert "line_item_product_code" in column_names
    for col in resp["Schema"]:
        assert col["Type"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
