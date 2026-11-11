"""political-view-changes-country-code."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "political-view-changes-country-code"
GROUP = "geocoding"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReverseGeocode on a position in Crimea with PoliticalView RUS returns country code RU and echoes
    PoliticalView RUS, while the default political view does not attribute it to RU.
    """
    geo = ctx.client("geo-places")
    position = [33.95876, 45.46824]  # Crimea, per AWS's own documented example

    default_resp = geo.reverse_geocode(QueryPosition=position, MaxResults=1)
    default_items = default_resp.get("ResultItems", [])
    assert default_items, "expected a default reverse-geocode result for the Crimea position"
    default_country = default_items[0]["Address"]["Country"]["Code2"]

    rus_resp = geo.reverse_geocode(QueryPosition=position, PoliticalView="RUS", MaxResults=1)
    rus_items = rus_resp.get("ResultItems", [])
    assert rus_items, "expected a reverse-geocode result under the RUS political view"
    rus_item = rus_items[0]
    assert rus_item["Address"]["Country"]["Code2"] == "RU", (
        f"PoliticalView=RUS must attribute Crimea to Russia, got {rus_item['Address']['Country']}"
    )
    assert rus_item.get("PoliticalView") == "RUS", (
        f"expected the echoed PoliticalView to be RUS, got {rus_item.get('PoliticalView')}"
    )
    assert default_country != "RU", (
        "expected the default (unspecified) political view to differ from the RUS-forced "
        f"attribution, but both resolved to {default_country}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
