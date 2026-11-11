"""configuration-sets-v1-and-v2-pagination-and-cross-api-token-continuation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-sets-v1-and-v2-pagination-and-cross-api-token-continuation"
GROUP = 'configuration-set-paging'
SERVICES = ['ses']

_MAX_PAGES = 1000
_MARGIN_S = 30.0


def _budget_left(ctx):
    left = ctx.time_left()
    return left is None or left > _MARGIN_S


def _walk_v1(ctx, ses, max_items):
    """Walk v1 ListConfigurationSets; return (names_in_order, pages, None)."""
    names, pages, token = [], [], None
    while len(pages) < _MAX_PAGES and _budget_left(ctx):
        kwargs = {'MaxItems': max_items}
        if token is not None:
            kwargs['NextToken'] = token
        resp = ses.list_configuration_sets(**kwargs)
        page = [cs['Name'] for cs in resp.get('ConfigurationSets') or []]
        pages.append(page)
        names.extend(page)
        token = resp.get('NextToken')
        if not token:
            return names, pages, None
    raise AssertionError(f'v1 configuration sets at MaxItems={max_items} still had a NextToken after {len(pages)} pages')


def _walk_v2(ctx, sesv2, page_size):
    """Walk v2 ListConfigurationSets (boto3 has no paginator for it); return (names, pages)."""
    names, pages, token = [], [], None
    while len(pages) < _MAX_PAGES and _budget_left(ctx):
        kwargs = {'PageSize': page_size}
        if token is not None:
            kwargs['NextToken'] = token
        resp = sesv2.list_configuration_sets(**kwargs)
        page = list(resp.get('ConfigurationSets') or [])
        pages.append(page)
        names.extend(page)
        token = resp.get('NextToken')
        if not token:
            return names, pages
    raise AssertionError(f'v2 configuration sets at PageSize={page_size} still had a NextToken after {len(pages)} pages')


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """v1 and v2 ListConfigurationSets page-walks each visit every set exactly once, and a v1
    NextToken continues in a v2 call without repeating page one.
    """
    v1 = ctx.client('ses')
    v2 = ctx.client('sesv2')

    mine = set()
    for i in range(3):
        name = ctx.unique_name(f'sim2real-behav-cfgset{i}-')
        v2.create_configuration_set(ConfigurationSetName=name)
        ctx.on_cleanup(lambda _n=name: v2.delete_configuration_set(ConfigurationSetName=_n))
        mine.add(name)

    v1_walked, v1_pages, _ = _walk_v1(ctx, v1, 1)
    for idx, page in enumerate(v1_pages):
        assert len(page) <= 1, f"v1 page {idx} returned {len(page)} items for MaxItems=1: {page!r}"
    dup = {n for n in v1_walked if v1_walked.count(n) > 1}
    assert not dup, f"v1 paginated ListConfigurationSets returned duplicates: {sorted(dup)}"
    missing = mine - set(v1_walked)
    assert not missing, f"v1 paginated walk dropped configuration sets that exist: {sorted(missing)}"

    v2_walked, v2_pages = _walk_v2(ctx, v2, 1)
    for idx, page in enumerate(v2_pages):
        assert len(page) <= 1, f"v2 page {idx} returned {len(page)} items for PageSize=1: {page!r}"
    dup2 = {n for n in v2_walked if v2_walked.count(n) > 1}
    assert not dup2, f"v2 paginated ListConfigurationSets returned duplicates: {sorted(dup2)}"
    missing2 = mine - set(v2_walked)
    assert not missing2, f"v2 paginated walk dropped configuration sets that exist: {sorted(missing2)}"

    first_page = v1.list_configuration_sets(MaxItems=1)
    token = first_page.get('NextToken')
    assert token, f"v1 ListConfigurationSets(MaxItems=1) with {len(mine)} sets present produced no NextToken"
    first_names = [cs['Name'] for cs in first_page.get('ConfigurationSets') or []]
    assert len(first_names) == 1, f"expected exactly one item on page one, got {first_names!r}"

    continued = v2.list_configuration_sets(NextToken=token)
    continued_names = list(continued.get('ConfigurationSets') or [])
    assert first_names[0] not in continued_names, (
        f"v1's NextToken continued into a v2 page that repeats page one's item {first_names[0]!r}: "
        f"{continued_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
