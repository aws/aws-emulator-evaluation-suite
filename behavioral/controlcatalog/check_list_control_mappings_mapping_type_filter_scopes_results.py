"""list-control-mappings-mapping-type-filter-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-control-mappings-mapping-type-filter-scopes-results"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MappingTypes=[FRAMEWORK] returns only FRAMEWORK mappings with the Framework union variant populated."""
    cc = ctx.client("controlcatalog")

    filtered = cc.list_control_mappings(
        MaxResults=50, Filter={"MappingTypes": ["FRAMEWORK"]}
    ).get("ControlMappings", [])
    assert filtered, "expected at least one FRAMEWORK control mapping in the catalog"

    for mapping in filtered:
        assert mapping["MappingType"] == "FRAMEWORK", (
            f"expected MappingType FRAMEWORK, got {mapping['MappingType']!r}"
        )
        detail = mapping["Mapping"]
        assert detail.get("Framework") is not None, "FRAMEWORK mapping missing Framework union variant"
        assert detail.get("CommonControl") is None, "FRAMEWORK mapping unexpectedly populated CommonControl"
        assert detail.get("RelatedControl") is None, "FRAMEWORK mapping unexpectedly populated RelatedControl"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
