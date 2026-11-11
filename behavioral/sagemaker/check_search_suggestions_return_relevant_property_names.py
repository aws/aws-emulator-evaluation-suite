"""search-suggestions-return-relevant-property-names."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-suggestions-return-relevant-property-names"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c2", "plane:control")
def run(ctx) -> None:
    """GetSearchSuggestions for a resource type surfaces property names that are
    actually derived from that account's data (e.g. a custom Tag key on a real
    Experiment), not a fixed/generic filler list unrelated to the hint."""
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-exp-")
    tag_key = ctx.unique_name("Sim2RealSuggestTag").replace("-", "")

    sm.create_experiment(ExperimentName=experiment_name, Tags=[{"Key": tag_key, "Value": "probe"}])
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    expected_property = f"tags.{tag_key}"
    matches = _poll_until(
        lambda: _matching_suggestions(sm, tag_key),
        lambda found: expected_property in found,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert expected_property in matches, (
        f"GetSearchSuggestions never surfaced the exact tag property {expected_property!r} "
        f"among suggestions matching the unique tag key {tag_key!r}; either suggestions are "
        f"unrelated to real account data or the custom tag was never indexed: got {matches!r}"
    )

    # Sanity: an unrelated, never-used hint must not be echoed back verbatim as if it were
    # a real property (guards against a suggester that fabricates suggestions from the hint
    # itself), and must not coincidentally surface our real tag key either.
    unrelated_hint = "CompletelyUnrelatedHintThatShouldNotMatchAnything"
    unrelated_resp = sm.get_search_suggestions(
        Resource="Experiment",
        SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": unrelated_hint}},
    )
    unrelated_names = [s["PropertyName"] for s in unrelated_resp.get("PropertyNameSuggestions", [])]
    assert unrelated_hint not in unrelated_names, (
        f"suggester echoed the unrelated hint back verbatim as a property name: {unrelated_names!r}"
    )
    assert expected_property not in unrelated_names, (
        f"unrelated hint {unrelated_hint!r} unexpectedly surfaced our real tag property "
        f"{expected_property!r}: {unrelated_names!r}"
    )


def _matching_suggestions(sm, hint: str) -> list[str]:
    resp = sm.get_search_suggestions(
        Resource="Experiment",
        SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": hint}},
    )
    names = [s["PropertyName"] for s in resp.get("PropertyNameSuggestions", [])]
    return [n for n in names if hint in n]


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
