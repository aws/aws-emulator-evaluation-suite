"""dedicated-ip-pool-paginator-walks-every-pool-once."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "dedicated-ip-pool-paginator-walks-every-pool-once"
GROUP = 'dedicated-ip-pool-paging'
SERVICES = ['sesv2']

_MAX_PAGES = 60


def _walk(sesv2, page_size):
    names, pages, token = [], [], None
    for _ in range(_MAX_PAGES):
        kwargs = {'PageSize': page_size}
        if token is not None:
            kwargs['NextToken'] = token
        resp = sesv2.list_dedicated_ip_pools(**kwargs)
        page = list(resp.get('DedicatedIpPools') or [])
        pages.append(page)
        names.extend(page)
        token = resp.get('NextToken')
        if not token:
            return names, pages
    raise AssertionError(f'more than {_MAX_PAGES} pages of dedicated IP pools at PageSize={page_size}')


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ListDedicatedIpPools walk at PageSize=1 visits every created pool exactly once, with
    at most one pool per page.
    """
    sesv2 = ctx.client('sesv2')

    mine = set()
    for i in range(3):
        name = ctx.unique_name(f'sim2real-behav-dip{i}-')
        sesv2.create_dedicated_ip_pool(PoolName=name, ScalingMode='STANDARD')
        ctx.on_cleanup(lambda _n=name: sesv2.delete_dedicated_ip_pool(PoolName=_n))
        mine.add(name)

    walked, pages = _walk(sesv2, 1)
    for idx, page in enumerate(pages):
        assert len(page) <= 1, f"page {idx} returned {len(page)} items for PageSize=1: {page!r}"
    dup = {n for n in walked if walked.count(n) > 1}
    assert not dup, f"paginated ListDedicatedIpPools returned duplicates: {sorted(dup)}"
    missing = mine - set(walked)
    assert not missing, f"paginated walk dropped pools that exist: {sorted(missing)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
