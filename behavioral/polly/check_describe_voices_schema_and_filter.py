"""describe-voices-schema-and-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-voices-schema-and-filter"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVoices returns the real Amazon Polly voice catalog: a known
    voice (Joanna) is present with the expected language/engine metadata,
    and filtering by LanguageCode narrows results to that exact language."""
    polly = ctx.client("polly")

    all_voices = _list_all(polly)
    by_id = {v["Id"]: v for v in all_voices}
    assert "Joanna" in by_id, f"expected Joanna in the unfiltered catalog, got {sorted(by_id)}"
    joanna = by_id["Joanna"]
    assert joanna["LanguageCode"] == "en-US", f"expected Joanna LanguageCode en-US, got {joanna['LanguageCode']}"
    assert joanna["Gender"] == "Female", f"expected Joanna Gender Female, got {joanna['Gender']}"
    assert "neural" in joanna["SupportedEngines"], f"expected neural in Joanna SupportedEngines, got {joanna['SupportedEngines']}"
    assert "standard" in joanna["SupportedEngines"], f"expected standard in Joanna SupportedEngines, got {joanna['SupportedEngines']}"

    en_gb = _list_all(polly, LanguageCode="en-GB")
    assert en_gb, "expected at least one en-GB voice"
    for voice in en_gb:
        assert voice["LanguageCode"] == "en-GB", f"expected only en-GB voices, got {voice['Id']}={voice['LanguageCode']}"
    en_gb_ids = {v["Id"] for v in en_gb}
    assert "Joanna" not in en_gb_ids, f"expected en-US voice Joanna excluded from en-GB filter, got {en_gb_ids}"


def _list_all(polly, **filters):
    out = []
    token = None
    while True:
        kwargs = dict(filters)
        if token:
            kwargs["NextToken"] = token
        resp = polly.describe_voices(**kwargs)
        out.extend(resp["Voices"])
        token = resp.get("NextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
