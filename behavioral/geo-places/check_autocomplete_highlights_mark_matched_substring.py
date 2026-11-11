"""autocomplete-highlights-mark-matched-substring."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "autocomplete-highlights-mark-matched-substring"
GROUP = "search"
SERVICES = ["geo-places"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Autocomplete for '1600 Pennsylvania Av' with AdditionalFeatures Core returns highlights whose
    StartIndex and EndIndex select their Value from the suggestion's Title, one of them matching '1600' or
    'pennsylvania'.
    """
    geo = ctx.client("geo-places")
    resp = geo.autocomplete(
        QueryText="1600 Pennsylvania Av",
        BiasPosition=[-77.0365, 38.8977],  # near the White House
        AdditionalFeatures=["Core"],
        MaxResults=5,
    )
    items = resp.get("ResultItems", [])
    assert items, "expected Autocomplete suggestions for '1600 Pennsylvania Av'"

    matches = [i for i in items if "1600" in i["Title"] and "pennsylvania" in i["Title"].lower()]
    assert matches, f"expected a '1600 Pennsylvania Ave' suggestion, got {[i['Title'] for i in items]}"
    item = matches[0]
    highlights = item.get("Highlights", {}).get("Title", [])
    assert highlights, "expected Highlights.Title to mark the matched substring"
    title = item["Title"]
    matched_values = {h["Value"].lower() for h in highlights}
    assert any("1600" in v or "pennsylvania" in v for v in matched_values), (
        f"expected a highlight covering the matched query terms, got {highlights} for title {title!r}"
    )
    for h in highlights:
        assert h["EndIndex"] > h["StartIndex"], f"highlight span is empty: {h}"
        assert title[h["StartIndex"]:h["EndIndex"]] == h["Value"], (
            f"highlight span {h} does not match title substring {title[h['StartIndex']:h['EndIndex']]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
