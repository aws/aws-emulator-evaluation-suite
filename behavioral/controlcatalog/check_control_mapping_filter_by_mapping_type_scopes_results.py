"""control-mapping-filter-by-mapping-type-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-mapping-filter-by-mapping-type-scopes-results"
GROUP = "data-integrity"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControlMappings with Filter.MappingTypes=[X] returns only mappings of type X."""
    cc = ctx.client("controlcatalog")
    unfiltered = cc.list_control_mappings(MaxResults=50)["ControlMappings"]
    distinct_types = {m["MappingType"] for m in unfiltered}
    assert len(distinct_types) > 1, (
        f"need >1 distinct MappingType on an unfiltered page to prove the filter narrows anything, "
        f"got {distinct_types}"
    )
    mapping_type = unfiltered[0]["MappingType"]

    filtered = cc.list_control_mappings(Filter={"MappingTypes": [mapping_type]}, MaxResults=50)
    items = filtered["ControlMappings"]

    assert len(items) >= 1, "filtering by the sample mapping's own MappingType returned nothing"
    assert all(m["MappingType"] == mapping_type for m in items), "filter did not scope all mappings to the mapping type"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
