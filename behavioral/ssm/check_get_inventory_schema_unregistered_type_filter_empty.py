"""get-inventory-schema-unregistered-type-filter-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-inventory-schema-unregistered-type-filter-empty"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInventorySchema filtered to a Custom: type name that was never registered returns an
    empty Schemas list rather than an error, while the same call for the built-in
    AWS:InstanceInformation type returns its schema."""
    ssm = ctx.client("ssm")

    builtin = ssm.get_inventory_schema(TypeName="AWS:InstanceInformation")["Schemas"]
    assert len(builtin) == 1, f"expected exactly one schema for AWS:InstanceInformation, got {builtin!r}"
    assert builtin[0]["TypeName"] == "AWS:InstanceInformation", builtin[0]
    attr_names = {a["Name"] for a in builtin[0]["Attributes"]}
    assert "InstanceId" in attr_names, sorted(attr_names)

    never_registered = "Custom:" + ctx.unique_name("S2RNeverPut").replace("-", "")
    unregistered = ssm.get_inventory_schema(TypeName=never_registered)["Schemas"]
    assert unregistered == [], (
        f"expected no schema for a never-registered type {never_registered!r}, got {unregistered!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
