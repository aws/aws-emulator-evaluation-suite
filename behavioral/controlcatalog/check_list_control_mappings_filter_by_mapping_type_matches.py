"""list-control-mappings-filter-by-mapping-type-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-control-mappings-filter-by-mapping-type-matches"
GROUP = "filtering"
SERVICES = ["controlcatalog"]

# The Mapping union variant that must be populated for each MappingType, and the only one.
_UNION_FIELD_BY_MAPPING_TYPE = {
    "FRAMEWORK": "Framework",
    "COMMON_CONTROL": "CommonControl",
    "RELATED_CONTROL": "RelatedControl",
}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControlMappings filtered by MappingType returns only mappings of that type, each with
    the matching Mapping union variant populated and every other variant absent."""
    cc = ctx.client("controlcatalog")
    baseline = cc.list_control_mappings(MaxResults=50)
    mappings = baseline.get("ControlMappings", [])
    assert mappings, "ListControlMappings returned no mappings"
    mapping_type = mappings[0]["MappingType"]
    expected_field = _UNION_FIELD_BY_MAPPING_TYPE[mapping_type]

    filtered = cc.list_control_mappings(Filter={"MappingTypes": [mapping_type]}, MaxResults=100)
    filtered_mappings = filtered.get("ControlMappings", [])
    assert filtered_mappings, f"filtering by MappingType={mapping_type} returned no mappings"
    for m in filtered_mappings:
        assert m["MappingType"] == mapping_type, (
            f"filter MappingTypes=[{mapping_type}] returned a {m['MappingType']} mapping"
        )
        detail = m["Mapping"]
        assert detail.get(expected_field) is not None, (
            f"{mapping_type} mapping missing its {expected_field} union variant"
        )
        for other_type, other_field in _UNION_FIELD_BY_MAPPING_TYPE.items():
            if other_field == expected_field:
                continue
            assert detail.get(other_field) is None, (
                f"{mapping_type} mapping unexpectedly populated {other_field} "
                f"(the union variant for {other_type})"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
