"""search-suggestions-reflects-created-resource-properties."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-suggestions-reflects-created-resource-properties"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSearchSuggestions surfaces a tag key from a freshly tagged
    experiment, proving suggestions are derived from live indexed state
    rather than a fixed/static list of property names."""
    sm = ctx.client("sagemaker")
    exp_name = ctx.unique_name("sim2real-behav-exp-")
    tag_key = ctx.unique_name("Sim2RealProbe-").replace("-", "")
    sm.create_experiment(ExperimentName=exp_name, Tags=[{"Key": tag_key, "Value": "probe-value"}])
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=exp_name))

    expected_property = f"tags.{tag_key}"
    deadline = time.monotonic() + 120
    property_names: set[str] = set()
    while time.monotonic() < deadline:
        resp = sm.get_search_suggestions(
            Resource="Experiment",
            SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": tag_key}},
        )
        property_names = {s["PropertyName"] for s in resp.get("PropertyNameSuggestions", [])}
        if expected_property in property_names:
            break
        time.sleep(5)

    assert expected_property in property_names, (
        f"expected {expected_property!r} in search suggestions within 120s, got {property_names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
