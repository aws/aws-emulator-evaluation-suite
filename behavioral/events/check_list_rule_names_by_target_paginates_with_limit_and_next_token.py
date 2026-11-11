"""list-rule-names-by-target-paginates-with-limit-and-next-token."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-rule-names-by-target-paginates-with-limit-and-next-token"
GROUP = 'targets'
SERVICES = ['events']


def _pages(ev, *, max_pages: int = 200, **kwargs):
    """Walk ListRuleNamesByTarget to exhaustion, returning the raw pages.

    Bounded by max_pages so a NextToken that never ends fails instead of looping forever.
    """
    pages = []
    token = None
    while True:
        call = dict(kwargs)
        if token is not None:
            call["NextToken"] = token
        page = ev.list_rule_names_by_target(**call)
        pages.append(page)
        token = page.get("NextToken")
        if not token:
            return pages
        assert len(pages) < max_pages, (
            f"ListRuleNamesByTarget still returned a NextToken after {len(pages)} pages over a "
            f"collection of a dozen rules; the cursor never terminates"
        )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRuleNamesByTarget pages ten rules on a fresh bus by Limit without drops or duplicates,
    ending with no NextToken, and a later RemoveTargets shrinks the paged result by exactly that
    rule.
    """
    ev = ctx.client("events")
    tag = [{"Key": "sim2real:managed", "Value": "true"}]

    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus, Tags=tag)
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    base = ctx.unique_name("sim2real-behav-rule-")
    pattern = json.dumps({"source": ["sim2real.lrnbt"]})
    target_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{ctx.unique_name('sim2real-behav-fn-')}"

    names = [f"{base}-{i:02d}" for i in range(10)]
    for name in names:
        ev.put_rule(Name=name, EventPattern=pattern, State="DISABLED", EventBusName=bus, Tags=tag)
        ctx.on_cleanup(lambda n=name: ev.delete_rule(Name=n, EventBusName=bus, Force=True))
        ev.put_targets(Rule=name, EventBusName=bus, Targets=[{"Id": "t1", "Arn": target_arn}])
        ctx.on_cleanup(lambda n=name: ev.remove_targets(Rule=n, EventBusName=bus, Ids=["t1"], Force=True))

    # --- unpaged: the closed collection is exactly what was created, no NextToken. -------------
    everything = ev.list_rule_names_by_target(TargetArn=target_arn, EventBusName=bus)
    assert sorted(everything["RuleNames"]) == sorted(names), (
        f"ListRuleNamesByTarget with no Limit must return exactly the 10 rules pointed at "
        f"{target_arn!r}; got {sorted(everything['RuleNames'])}"
    )
    assert "NextToken" not in everything, (
        f"an unpaged call that returned all {len(names)} rules must not carry a NextToken, got "
        f"{everything.get('NextToken')!r}"
    )

    # --- paging with Limit=3, then Limit=1 -----------------------------------------------------
    for limit, min_pages in ((3, 4), (1, len(names))):
        pages = _pages(ev, TargetArn=target_arn, EventBusName=bus, Limit=limit)
        got = [n for page in pages for n in page["RuleNames"]]
        assert len(pages) >= min_pages, (
            f"Limit={limit} over {len(names)} rules must take at least {min_pages} pages, took "
            f"{len(pages)}"
        )
        for i, page in enumerate(pages):
            assert len(page["RuleNames"]) <= limit, (
                f"page {i} of a Limit={limit} walk returned {len(page['RuleNames'])} names, more "
                f"than the requested limit"
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
        assert len(got) == len(set(got)), (
            f"Limit={limit} walk returned duplicates: "
            f"{sorted(n for n in set(got) if got.count(n) > 1)}"
        )
        assert sorted(got) == sorted(names), (
            f"Limit={limit} walk lost or invented rule names. missing="
            f"{sorted(set(names) - set(got))} extra={sorted(set(got) - set(names))}"
        )

    # --- effect: RemoveTargets on one rule shrinks every subsequent page walk by exactly it. ----
    removed = names[0]
    remaining = names[1:]
    ev.remove_targets(Rule=removed, EventBusName=bus, Ids=["t1"], Force=True)
    pages = _pages(ev, TargetArn=target_arn, EventBusName=bus, Limit=3)
    got = sorted(n for page in pages for n in page["RuleNames"])
    assert got == sorted(remaining), (
        f"after RemoveTargets({removed}), a paged walk over {target_arn!r} must return exactly the "
        f"remaining {len(remaining)} rules; got {got}"
    )
    assert removed not in got, (
        f"{removed!r} had its target removed and must not appear in any page of "
        f"ListRuleNamesByTarget, got pages containing {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
