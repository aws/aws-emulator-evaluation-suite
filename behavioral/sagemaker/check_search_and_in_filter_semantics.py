"""search-and-in-filter-semantics."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-and-in-filter-semantics"
GROUP = 'search'
SERVICES = ['sagemaker']

_TAG_KEY = "sim2realsuite"


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _create_experiment(ctx, name, nonce):
    sm = ctx.client("sagemaker")
    sm.create_experiment(
        ExperimentName=name,
        DisplayName=name,
        Description="sim2real behavioral search fixture",
        Tags=[{"Key": _TAG_KEY, "Value": nonce}],
    )
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=name))
    return name


def _search_names(ctx, expression):
    sm = ctx.client("sagemaker")
    resp = sm.search(
        Resource="Experiment", SearchExpression=expression, MaxResults=100
    )
    return sorted(
        r["Experiment"]["ExperimentName"] for r in resp.get("Results", [])
    )


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Search over Experiments tagged per run applies AND across filters and OR
    across an In list, returning exactly the expected names, and returns [] for an
    unsatisfiable conjunction and for the tag's Equals plus its own NotExists.
    """
    nonce = ctx.unique_name("sim2real-behav-exp-")
    timeout_s = 300
    names = [f"{nonce}-alpha", f"{nonce}-beta", f"{nonce}-gamma"]
    for name in names:
        _create_experiment(ctx, name, nonce)

    tag_filter = {
        "Name": f"Tags.{_TAG_KEY}",
        "Operator": "Equals",
        "Value": nonce,
    }

    # The search index is asynchronous; poll the baseline to a bounded deadline.
    all_three = _poll(
        lambda: _search_names(ctx, {"Filters": [tag_filter], "Operator": "And"}),
        lambda got: got == sorted(names),
        timeout_s=timeout_s,
    )
    assert all_three == sorted(names), (
        f"Search by tag returned {all_three}, expected {sorted(names)} -- "
        f"either the index never converged or the tag filter is not honoured"
    )

    # AND across two filters narrows; `In` is OR across the comma-delimited values.
    both = _search_names(
        ctx,
        {
            "Operator": "And",
            "Filters": [
                tag_filter,
                {
                    "Name": "DisplayName",
                    "Operator": "In",
                    "Value": f"{names[0]},{names[2]}",
                },
            ],
        },
    )
    assert both == sorted([names[0], names[2]]), (
        f"And(tag, In(alpha,gamma)) returned {both}, expected "
        f"{sorted([names[0], names[2]])} -- an emulator that ignores one filter "
        f"or treats `In` as equality fails here"
    )

    # A single-valued `In` must behave like equality, not like a prefix match.
    only_beta = _search_names(
        ctx,
        {
            "Operator": "And",
            "Filters": [
                tag_filter,
                {"Name": "DisplayName", "Operator": "In", "Value": names[1]},
            ],
        },
    )
    assert only_beta == [names[1]], (
        f"And(tag, In(beta)) returned {only_beta}, expected [{names[1]}]"
    )

    # An unsatisfiable conjunction must return an empty result set -- not an
    # error, and not the unfiltered set. The value cannot ever exist because it
    # carries the run nonce, so this is empty by construction, not by index lag.
    empty = _search_names(
        ctx,
        {
            "Operator": "And",
            "Filters": [
                tag_filter,
                {
                    "Name": "DisplayName",
                    "Operator": "Equals",
                    "Value": f"{nonce}-never",
                },
            ],
        },
    )
    assert empty == [], (
        f"unsatisfiable conjunction returned {empty} -- an emulator that ANDs "
        f"nothing and returns everything is the #1 Search stub failure mode"
    )

    # Exists must discriminate: every fixture has the tag, none has a Description
    # property that is absent, so NotExists on the tag must return none of ours.
    not_exists = _search_names(
        ctx,
        {
            "Operator": "And",
            "Filters": [
                tag_filter,
                {"Name": f"Tags.{_TAG_KEY}", "Operator": "NotExists"},
            ],
        },
    )
    assert not_exists == [], (
        f"And(Equals tag, NotExists same tag) returned {not_exists}; a "
        f"contradiction must yield nothing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
