"""get-search-suggestions-returns-results-for-existing-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-search-suggestions-returns-results-for-existing-resource"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSearchSuggestions for the Experiment resource surfaces a freshly created, uniquely named tag key
    once indexed, and an unrelated hint does not surface that key.
    """
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-experiment-")
    tag_key = ctx.unique_name("sim2realSearchTag")

    sm.create_experiment(ExperimentName=experiment_name, Tags=[{"Key": tag_key, "Value": "probe"}])
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    hint = tag_key[: len(tag_key) - 4]  # a distinctive prefix unlikely to collide with other tags

    resp = _poll_until(
        lambda: sm.get_search_suggestions(
            Resource="Experiment",
            SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": hint}},
        ),
        lambda r: any(tag_key in s.get("PropertyName", "") for s in r.get("PropertyNameSuggestions", [])),
        timeout_s=120.0,
        interval_s=5.0,
    )

    names = {s["PropertyName"] for s in resp["PropertyNameSuggestions"]}
    assert any(tag_key in n for n in names), (
        f"expected a suggestion containing the freshly-created tag key {tag_key!r} for hint "
        f"{hint!r}, got {names}"
    )

    # An unrelated hint that shares no prefix with our tag key must not surface it --
    # otherwise "suggestions" are really just everything indexed, unfiltered by hint.
    unrelated = sm.get_search_suggestions(
        Resource="Experiment",
        SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": "ZzUnrelatedNoMatch987"}},
    )
    unrelated_names = {s["PropertyName"] for s in unrelated.get("PropertyNameSuggestions", [])}
    assert not any(tag_key in n for n in unrelated_names), (
        f"unrelated hint unexpectedly surfaced the tag key {tag_key!r}: {unrelated_names}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
