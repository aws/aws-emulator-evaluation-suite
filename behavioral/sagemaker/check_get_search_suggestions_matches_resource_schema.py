"""get-search-suggestions-matches-resource-schema."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-search-suggestions-matches-resource-schema"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSearchSuggestions suggests a freshly tagged Experiment's tag key but never the top-level schema
    field ExperimentName nor a hint that matches no property, because it indexes only HyperParameters, Tags
    and Metrics.
    """
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-exp-")
    tag_key = ctx.unique_name("Sim2RealSchemaProbe").replace("-", "")

    sm.create_experiment(ExperimentName=experiment_name, Tags=[{"Key": tag_key, "Value": "probe"}])
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    indexed = _poll_until(
        lambda: [
            s["PropertyName"]
            for s in sm.get_search_suggestions(
                Resource="Experiment",
                SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": tag_key}},
            ).get("PropertyNameSuggestions", [])
        ],
        lambda names: any(tag_key in n for n in names),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert any(tag_key in n for n in indexed), (
        f"positive control failed: expected the just-created tag {tag_key!r} to be "
        f"indexed and suggested, got {indexed!r}"
    )

    # ExperimentName is a real, fixed, always-present schema field of Experiment -- but
    # it is not a HyperParameters/Tags/Metrics property, so it must never be suggested,
    # even though it exactly names a real property of the resource.
    schema_field = sm.get_search_suggestions(
        Resource="Experiment",
        SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": "ExperimentName"}},
    )
    schema_field_suggestions = [s["PropertyName"] for s in schema_field.get("PropertyNameSuggestions", [])]
    assert "ExperimentName" not in schema_field_suggestions, (
        f"'ExperimentName' is a fixed top-level schema field, not an indexed "
        f"Tags/HyperParameters/Metrics property, but it was suggested: {schema_field_suggestions!r}"
    )

    # A hint that matches no real property at all must not fabricate a hit either.
    bogus = sm.get_search_suggestions(
        Resource="Experiment",
        SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": "ZzzNotARealPropertyZzz"}},
    )
    bogus_suggestions = [s["PropertyName"] for s in bogus.get("PropertyNameSuggestions", [])]
    assert "ZzzNotARealPropertyZzz" not in bogus_suggestions, (
        f"hint 'ZzzNotARealPropertyZzz' matches no real property, but it was echoed "
        f"back as a suggestion: {bogus_suggestions!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
