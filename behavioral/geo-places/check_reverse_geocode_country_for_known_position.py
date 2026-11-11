"""reverse-geocode-country-for-known-position."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reverse-geocode-country-for-known-position"
GROUP = "geocoding"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReverseGeocode on the Statue of Liberty's coordinates returns Title 'Statue of Liberty', country US,
    region NY and locality New York, at a Position within 0.01 degrees of the query.
    """
    geo = ctx.client("geo-places")
    # Statue of Liberty: 40.6892 N, 74.0445 W. Position is [longitude, latitude].
    query_position = [-74.0445, 40.6892]
    resp = geo.reverse_geocode(QueryPosition=query_position, MaxResults=1)
    items = resp.get("ResultItems", [])
    assert items, "expected a reverse-geocode result for the Statue of Liberty's coordinates"
    item = items[0]

    address = item["Address"]
    country = address["Country"]
    assert country["Code2"] == "US", f"expected country code US, got {country}"
    assert item["Title"] == "Statue of Liberty", f"expected the Statue of Liberty, got {item['Title']}"
    assert address["Region"]["Code"] == "NY", f"expected region NY, got {address['Region']}"
    assert address["Locality"] == "New York", f"expected locality New York, got {address['Locality']}"

    lng, lat = item["Position"]
    assert abs(lng - query_position[0]) < 0.01 and abs(lat - query_position[1]) < 0.01, (
        f"echoed Position {item['Position']} is not near the query position {query_position}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
