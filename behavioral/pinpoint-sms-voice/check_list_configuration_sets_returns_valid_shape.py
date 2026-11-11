"""list-configuration-sets-returns-valid-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-configuration-sets-returns-valid-shape"
GROUP = "state"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConfigurationSets returns ConfigurationSets as a list of strings on every page, and NextToken
    pagination terminates."""
    client = ctx.client("pinpoint-sms-voice")

    names: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = client.list_configuration_sets(**kwargs)
        assert "ConfigurationSets" in resp, f"response missing ConfigurationSets key: {resp!r}"
        page_names = resp["ConfigurationSets"]
        assert isinstance(page_names, list), f"ConfigurationSets must be a list, got {type(page_names).__name__}"
        assert all(isinstance(n, str) for n in page_names), f"ConfigurationSets entries must be strings: {page_names!r}"
        names.extend(page_names)
        token = resp.get("NextToken")
        pages += 1
        if not token or pages > 5000:
            break
    assert pages <= 5000, "pagination never terminated"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
