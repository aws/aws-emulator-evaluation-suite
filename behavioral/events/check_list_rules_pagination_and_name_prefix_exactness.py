"""list-rules-pagination-and-name-prefix-exactness."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-rules-pagination-and-name-prefix-exactness"
GROUP = 'rule'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRules paginates without drops, duplicates or a trailing NextToken, and NamePrefix is an
    anchored, case-sensitive prefix filter that composes with pagination.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListRules.html
    """
    # A brand-new custom bus makes the collection closed, so results are compared by equality.
    ev = ctx.client("events")
    tags = [{"Key": "sim2real:managed", "Value": "true"}]

    # Registered before the rules so the LIFO cleanup order deletes the rules first: an event bus
    # that still has rules on it cannot be deleted.
    bus = ctx.unique_name("sim2real-behav-")
    ev.create_event_bus(Name=bus, Tags=tags)
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    base = ctx.unique_name("sim2real-behav-")
    pattern = json.dumps({"source": ["sim2real.orders"]})

    alpha = [f"{base}-alpha{i:02d}" for i in range(8)]
    beta = [f"{base}-beta{i:02d}" for i in range(4)]
    created = alpha + beta
    for name in created:
        ev.put_rule(Name=name, EventPattern=pattern, State="DISABLED", EventBusName=bus, Tags=tags)
        ctx.on_cleanup(lambda n=name: ev.delete_rule(Name=n, EventBusName=bus))
    for name in created:
        assert len(name) <= 64, f"rule name {name!r} is {len(name)} chars, over the 64-char maximum"

    everything = ev.list_rules(EventBusName=bus)
    assert sorted(r["Name"] for r in everything["Rules"]) == sorted(created), (
        f"a freshly created bus must contain exactly the rules this check created; got "
        f"{sorted(r['Name'] for r in everything['Rules'])}"
    )
    assert "NextToken" not in everything, (
        f"an unpaged ListRules that returned all {len(created)} rules must not carry a NextToken, "
        f"got {everything.get('NextToken')!r}"
    )

    for limit, min_pages in ((5, 3), (1, len(created))):
        pages = _pages(ev, EventBusName=bus, Limit=limit)
        names = [r["Name"] for page in pages for r in page["Rules"]]
        assert len(pages) >= min_pages, (
            f"Limit={limit} over {len(created)} rules must take at least {min_pages} pages, "
            f"took {len(pages)}"
        )
        for i, page in enumerate(pages):
            assert len(page["Rules"]) <= limit, (
                f"page {i} of a Limit={limit} walk returned {len(page['Rules'])} rules, "
                f"more than the requested limit"
            )
        for i, page in enumerate(pages[:-1]):
            assert page.get("NextToken"), (
                f"page {i} of {len(pages)} is not the last page, so it must carry a NextToken"
            )
        assert "NextToken" not in pages[-1], (
            f"the LAST page of a Limit={limit} walk must not carry a NextToken, got "
            f"{pages[-1].get('NextToken')!r}; an always-present NextToken makes every caller's "
            f"pagination loop non-terminating"
        )
        assert len(names) == len(set(names)), (
            f"Limit={limit} walk returned duplicates: "
            f"{sorted(n for n in set(names) if names.count(n) > 1)}"
        )
        assert sorted(names) == sorted(created), (
            f"Limit={limit} walk lost or invented rules. missing="
            f"{sorted(set(created) - set(names))} extra={sorted(set(names) - set(created))}"
        )

    got_alpha = sorted(r["Name"] for r in ev.list_rules(EventBusName=bus,
                                                        NamePrefix=f"{base}-alpha")["Rules"])
    assert got_alpha == sorted(alpha), (
        f"NamePrefix must return exactly the 8 alpha rules, got {got_alpha}"
    )
    got_beta = sorted(r["Name"] for r in ev.list_rules(EventBusName=bus,
                                                       NamePrefix=f"{base}-beta")["Rules"])
    assert got_beta == sorted(beta), (
        f"NamePrefix must return exactly the 4 beta rules, got {got_beta}"
    )

    # Adding an unrelated rule must not disturb the alpha result.
    contains = f"{base}-zz-alpha-suffix"
    ev.put_rule(Name=contains, EventPattern=pattern, State="DISABLED", EventBusName=bus, Tags=tags)
    ctx.on_cleanup(lambda: ev.delete_rule(Name=contains, EventBusName=bus))
    after = sorted(r["Name"] for r in ev.list_rules(EventBusName=bus,
                                                    NamePrefix=f"{base}-alpha")["Rules"])
    assert after == sorted(alpha), (
        f"adding {contains!r} must not change the {base}-alpha result, got {after}"
    )
    assert contains in {r["Name"] for r in ev.list_rules(EventBusName=bus)["Rules"]}, (
        f"control failed: {contains!r} must appear in the UNfiltered listing"
    )

    # Anchored, not a substring search: `zz-alpha` occurs mid-name in `contains` and starts no
    # rule, so a prefix filter returns nothing while a substring filter would return it.
    mid = sorted(r["Name"] for r in ev.list_rules(EventBusName=bus,
                                                  NamePrefix="zz-alpha")["Rules"])
    assert mid == [], (
        f"NamePrefix is anchored at the start, not a substring search: 'zz-alpha' occurs only in "
        f"the MIDDLE of {contains!r} and begins no rule name, so the filtered result must be "
        f"empty, got {mid}"
    )

    upper = ev.list_rules(EventBusName=bus, NamePrefix=f"{base}-ALPHA")["Rules"]
    assert upper == [], (
        f"NamePrefix must be case-sensitive; the upper-cased prefix matched "
        f"{[r['Name'] for r in upper]}"
    )

    # A prefix that matches nothing: empty list, and no NextToken to chase.
    none = ev.list_rules(EventBusName=bus, NamePrefix=f"{base}-gamma")
    assert none["Rules"] == [], (
        f"a NamePrefix matching nothing must return an empty Rules list, got "
        f"{[r['Name'] for r in none['Rules']]}"
    )
    assert "NextToken" not in none, (
        f"an empty filtered result must not carry a NextToken, got {none.get('NextToken')!r}"
    )

    pages = _pages(ev, EventBusName=bus, NamePrefix=f"{base}-alpha", Limit=3)
    names = [r["Name"] for page in pages for r in page["Rules"]]
    assert sorted(names) == sorted(alpha), (
        f"paging a FILTERED listing must reconstruct only the filtered set; got {sorted(names)}"
    )
    assert len(names) == len(set(names)), f"paged filtered walk returned duplicates: {names}"


def _pages(ev, *, max_pages: int = 200, **kwargs):
    """Walk ListRules to exhaustion, returning the raw pages; bounded by max_pages so an
    always-present NextToken fails instead of looping forever."""
    pages = []
    token = None
    while True:
        call = dict(kwargs)
        if token is not None:
            call["NextToken"] = token
        page = ev.list_rules(**call)
        pages.append(page)
        token = page.get("NextToken")
        if not token:
            return pages
        assert len(pages) < max_pages, (
            f"ListRules still returned a NextToken after {len(pages)} pages over a collection of "
            f"at most a few dozen rules; the cursor never terminates"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
