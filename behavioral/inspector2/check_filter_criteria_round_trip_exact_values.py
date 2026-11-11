"""filter-criteria-round-trip-exact-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-criteria-round-trip-exact-values"
GROUP = "data-plane"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The exact filterCriteria structure passed to CreateFilter is preserved verbatim on read-back."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-filter-crit-")

    criteria = {
        "severity": [
            {"comparison": "EQUALS", "value": "HIGH"},
            {"comparison": "EQUALS", "value": "CRITICAL"},
        ],
        "resourceType": [{"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"}],
        "findingType": [{"comparison": "NOT_EQUALS", "value": "NETWORK_REACHABILITY"}],
    }

    created = inspector2.create_filter(
        action="SUPPRESS",
        name=name,
        description="round-trip fidelity check",
        filterCriteria=criteria,
        tags={"sim2real": "true"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: inspector2.delete_filter(arn=arn))

    found = _find_filter(inspector2, arn)
    assert found is not None, "created filter not found via ListFilters"

    got_criteria = found["criteria"]
    for field, expected_list in criteria.items():
        got_list = got_criteria.get(field)
        assert got_list is not None, f"field {field} missing from returned filterCriteria"
        got_pairs = sorted((sf["comparison"], sf["value"]) for sf in got_list)
        expected_pairs = sorted((sf["comparison"], sf["value"]) for sf in expected_list)
        assert got_pairs == expected_pairs, f"field {field} mismatch: {got_pairs} != {expected_pairs}"

    assert found["action"] == "SUPPRESS"
    assert found["description"] == "round-trip fidelity check"


def _find_filter(inspector2, arn: str):
    next_token = None
    while True:
        kwargs = {"maxResults": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = inspector2.list_filters(**kwargs)
        for f in resp.get("filters", []):
            if f["arn"] == arn:
                return f
        next_token = resp.get("nextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
