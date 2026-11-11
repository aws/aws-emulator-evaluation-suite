"""get-tax-exemption-types-returns-populated-catalog."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-tax-exemption-types-returns-populated-catalog"
GROUP = "state"
SERVICES = ["taxsettings"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTaxExemptionTypes returns a non-empty catalog with unique, non-blank display names and descriptions and
    well-formed, unique jurisdictions, and a second read returns the same catalog."""
    ts = ctx.client("taxsettings")
    types = ts.get_tax_exemption_types()["taxExemptionTypes"]
    assert len(types) > 0, f"expected a non-empty taxExemptionTypes catalog, got {types!r}"

    names = [entry["displayName"] for entry in types]
    assert len(set(names)) == len(names), f"expected unique displayName values, got {names!r}"
    for entry in types:
        assert re.fullmatch(r"\S(.*\S)?", entry["displayName"]), (
            f"expected a non-blank, unpadded displayName on {entry!r}"
        )
        assert re.fullmatch(r"\S(.*\S)?", entry["description"]), (
            f"expected a non-blank, unpadded description on {entry!r}"
        )
        jurisdictions = entry["applicableJurisdictions"]
        assert len(jurisdictions) > 0, f"expected at least one jurisdiction on {entry!r}"
        keys = [(j["country"], j.get("state")) for j in jurisdictions]
        assert len(set(keys)) == len(keys), f"expected no duplicate jurisdictions on {entry!r}"
        for country, state in keys:
            assert re.fullmatch(r"[A-Z]{2}", country), (
                f"expected an ISO 3166-1 alpha-2 country on {entry['displayName']!r}, got {country!r}"
            )
            assert state is None or re.fullmatch(r"[A-Z]{2}", state), (
                f"expected a two-letter state code on {entry['displayName']!r}, got {state!r}"
            )

    # Reference data, not account state: an independent second read returns the same catalog.
    again = ts.get_tax_exemption_types()["taxExemptionTypes"]
    assert _canonical(again) == _canonical(types), (
        "expected GetTaxExemptionTypes to return the same catalog on a second read"
    )


def _canonical(types):
    return sorted(
        (
            e["displayName"],
            e["description"],
            tuple(sorted((j["country"], j.get("state") or "") for j in e["applicableJurisdictions"])),
        )
        for e in types
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
