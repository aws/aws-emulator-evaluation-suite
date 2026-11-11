"""get-search-suggestions-reflects-created-resource."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "get-search-suggestions-reflects-created-resource"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After tagging a new Experiment, GetSearchSuggestions surfaces the new Tags.<key> property name."""
    sm = ctx.client("sagemaker")
    tag_key = "sim2realbehavtag" + uuid.uuid4().hex[:8]
    experiment_name = ctx.unique_name("sim2real-sm-exp-")

    sm.create_experiment(
        ExperimentName=experiment_name,
        Tags=[{"Key": tag_key, "Value": "sim2real-behavioral-check"}],
    )
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    # The hint is a strict prefix of the tag key, not the whole key -- a suggester that merely
    # echoed its input back would satisfy a hint == expected-answer query without ever indexing
    # anything real, so the completion beyond the literal hint is what proves this. The property
    # is lowercase "tags.<key>", not "Tags.<key>"; AWS returns the former.
    expected_property = f"tags.{tag_key}"
    hint = tag_key[:-4]

    suggestions = _poll_until(
        lambda: sm.get_search_suggestions(
            Resource="Experiment",
            SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": hint}},
        )["PropertyNameSuggestions"],
        lambda s: any(item.get("PropertyName") == expected_property for item in s),
        timeout_s=120.0,
        interval_s=5.0,
    )
    property_names = {item["PropertyName"] for item in suggestions}
    assert expected_property in property_names, (
        f"expected {expected_property} in search suggestions for hint {hint!r} after tagging a "
        f"new Experiment, got {property_names}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
