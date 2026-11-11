"""list-services-max-results-page-size-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-services-max-results-page-size-respected"
GROUP = "list"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServices returns exactly maxResults items, not merely at most that many,
    when the catalog holds more entries than the requested page size."""
    uxc = ctx.client("uxc")

    catalog_page = uxc.list_services(maxResults=1000)
    catalog_size = len(catalog_page["services"])
    assert catalog_size > 3, (
        f"catalog holds only {catalog_size} services; too small to exercise the "
        "maxResults=3 boundary"
    )

    page = uxc.list_services(maxResults=3)
    services = page["services"]
    assert len(services) == 3, (
        f"expected exactly 3 services for maxResults=3 against a {catalog_size}-entry "
        f"catalog, got {len(services)}"
    )
    assert page.get("nextToken"), (
        "expected a nextToken since the catalog has more entries than the 3 returned"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
