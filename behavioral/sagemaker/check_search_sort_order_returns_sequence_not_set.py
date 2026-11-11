"""search-sort-order-returns-sequence-not-set."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "search-sort-order-returns-sequence-not-set"
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
        Tags=[{"Key": _TAG_KEY, "Value": nonce}],
    )
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=name))


def _search_ordered(ctx, expression, *, sort_by=None, sort_order=None):
    """Return the result names in the order the service returned them (a sequence,
    deliberately NOT a set, because the sort order is part of the contract)."""
    sm = ctx.client("sagemaker")
    kwargs = {
        "Resource": "Experiment",
        "SearchExpression": expression,
        "MaxResults": 100,
    }
    if sort_by is not None:
        kwargs["SortBy"] = sort_by
    if sort_order is not None:
        kwargs["SortOrder"] = sort_order
    resp = sm.search(**kwargs)
    assert isinstance(resp.get("Results"), list), (
        f"Search Results must be an ordered list, got {type(resp.get('Results'))}"
    )
    return [r["Experiment"]["ExperimentName"] for r in resp["Results"]]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Search with SortBy/SortOrder returns the per-run population as an ordered
    list: Ascending matches the expected order, Descending is its exact reverse,
    and a Contains filter narrows the result to the one expected item.
    """
    nonce = ctx.unique_name("sim2real-behav-exp-")
    timeout_s = 300
    # Names chosen so lexical order is unambiguous and independent of creation
    # order: created c, a, b -- so a name-sorted answer cannot be creation order.
    ascending = [f"{nonce}-a", f"{nonce}-b", f"{nonce}-c"]
    for name in (ascending[2], ascending[0], ascending[1]):
        _create_experiment(ctx, name, nonce)

    expression = {
        "Operator": "And",
        "Filters": [
            {"Name": f"Tags.{_TAG_KEY}", "Operator": "Equals", "Value": nonce}
        ],
    }

    got_asc = _poll(
        lambda: _search_ordered(
            ctx, expression, sort_by="ExperimentName", sort_order="Ascending"
        ),
        lambda got: sorted(got) == ascending,
        timeout_s=timeout_s,
    )
    assert got_asc == ascending, (
        f"SortOrder=Ascending on ExperimentName returned {got_asc}, expected "
        f"{ascending} -- a sorted *sequence*, not merely the right membership"
    )

    got_desc = _search_ordered(
        ctx, expression, sort_by="ExperimentName", sort_order="Descending"
    )
    assert got_desc == list(reversed(ascending)), (
        f"SortOrder=Descending returned {got_desc}, expected "
        f"{list(reversed(ascending))}"
    )
    assert got_desc != got_asc, (
        "Ascending and Descending returned the identical sequence -- SortOrder "
        "is being accepted and ignored"
    )

    # Contains is a substring predicate on a text property, and the docs allow
    # exactly one Contains per expression for non-Experiment properties; on
    # Experiment.DisplayName it is explicitly allowed. It must narrow by substring,
    # not by equality, and the ordering must survive the extra filter.
    contains = _search_ordered(
        ctx,
        {
            "Operator": "And",
            "Filters": [
                {"Name": f"Tags.{_TAG_KEY}", "Operator": "Equals", "Value": nonce},
                {
                    "Name": "DisplayName",
                    "Operator": "Contains",
                    "Value": f"{nonce}-b",
                },
            ],
        },
        sort_by="ExperimentName",
        sort_order="Ascending",
    )
    assert contains == [ascending[1]], (
        f"Contains on DisplayName returned {contains}, expected [{ascending[1]}] "
        f"-- an emulator that maps Contains onto equality or onto 'match all' "
        f"fails here"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
