"""describe-ops-items-filters-combine-with-and-semantics-and-paginate."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-ops-items-filters-combine-with-and-semantics-and-paginate"
GROUP = "filtering"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeOpsItems ANDs several OpsItemFilters together, Title Contains matches a
    substring, and paging with MaxResults smaller than the result set assembles the
    same set that one unpaged call returns."""
    ssm = ctx.client("ssm")
    source = ctx.unique_name("sim2real-ops-filter-")

    items = {}
    for label, priority in (("alpha", 1), ("beta", 3), ("gamma", 5)):
        title = f"sim2real {label} {source}"
        ops_item_id = ssm.create_ops_item(
            Title=title,
            Description="sim2real behavioral test ops item",
            Source=source,
            Priority=priority,
        )["OpsItemId"]
        ctx.on_cleanup(lambda _id=ops_item_id: ssm.delete_ops_item(OpsItemId=_id))
        items[label] = (ops_item_id, title)

    expected_ids = {ops_item_id for ops_item_id, _ in items.values()}

    def _source_filter():
        return [{"Key": "Source", "Values": [source], "Operator": "Equal"}]

    def _describe(filters, *, max_results=None):
        kwargs = {"OpsItemFilters": filters}
        if max_results is not None:
            kwargs["MaxResults"] = max_results
        ids = []
        next_token = None
        for _ in range(10):
            page_kwargs = dict(kwargs)
            if next_token:
                page_kwargs["NextToken"] = next_token
            page = ssm.describe_ops_items(**page_kwargs)
            ids.extend(s["OpsItemId"] for s in page["OpsItemSummaries"])
            next_token = page.get("NextToken")
            if not next_token:
                break
        return ids

    def _poll(filters, predicate, *, max_results=None, attempts=15, delay=2.0):
        """DescribeOpsItems is backed by an eventually-consistent index."""
        ids = _describe(filters, max_results=max_results)
        for _ in range(attempts):
            if predicate(ids):
                return ids
            time.sleep(delay)
            ids = _describe(filters, max_results=max_results)
        return ids

    # Paging one item at a time must assemble the identical set an unpaged call returns.
    paged_ids = _poll(_source_filter(), lambda ids: set(ids) == expected_ids, max_results=1)
    assert set(paged_ids) == expected_ids, (
        f"paged DescribeOpsItems returned {sorted(set(paged_ids))}, expected {sorted(expected_ids)}"
    )
    assert len(paged_ids) == len(expected_ids), (
        f"paging duplicated or dropped an id: {paged_ids}"
    )

    # Two filters AND together: Source narrows to this check's items, Priority narrows further.
    priority_ids = _poll(
        _source_filter() + [{"Key": "Priority", "Values": ["3"], "Operator": "Equal"}],
        lambda ids: set(ids) == {items["beta"][0]},
    )
    assert set(priority_ids) == {items["beta"][0]}, (
        f"Source+Priority filter returned {sorted(set(priority_ids))}, expected only beta"
    )

    # Title Contains matches a substring, not only a full-value equality.
    contains_ids = _poll(
        _source_filter() + [{"Key": "Title", "Values": ["beta"], "Operator": "Contains"}],
        lambda ids: set(ids) == {items["beta"][0]},
    )
    assert set(contains_ids) == {items["beta"][0]}, (
        f"Title Contains 'beta' returned {sorted(set(contains_ids))}, expected only beta"
    )

    # A Contains value that matches none of this check's titles returns none of them.
    no_match_ids = _describe(
        _source_filter() + [{"Key": "Title", "Values": ["zzz-nomatch"], "Operator": "Contains"}]
    )
    assert set(no_match_ids) & expected_ids == set(), (
        f"a non-matching Title Contains value still returned this check's items: {no_match_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
