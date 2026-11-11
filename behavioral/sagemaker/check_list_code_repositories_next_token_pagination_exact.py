"""list-code-repositories-next-token-pagination-exact."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-code-repositories-next-token-pagination-exact"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']



def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_code_repository(ctx, name):
    sm = ctx.client("sagemaker")
    sm.create_code_repository(
        CodeRepositoryName=name,
        GitConfig={
            "RepositoryUrl": "https://example.com/sim2real/example-repo.git",
            "Branch": "main",
        },
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_code_repository(CodeRepositoryName=name))
    return name


def _pages(ctx, *, name_contains, max_results, page_cap=10):
    """Walk ListCodeRepositories by NextToken, returning the per-page name lists."""
    sm = ctx.client("sagemaker")
    pages = []
    token = None
    for _ in range(page_cap):
        kwargs = {
            "NameContains": name_contains,
            "MaxResults": max_results,
            "SortBy": "Name",
            "SortOrder": "Ascending",
        }
        if token is not None:
            kwargs["NextToken"] = token
        resp = sm.list_code_repositories(**kwargs)
        pages.append(
            [s["CodeRepositoryName"] for s in resp["CodeRepositorySummaryList"]]
        )
        token = resp.get("NextToken")
        if not token:
            return pages, False
    return pages, True


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCodeRepositories NextToken pagination is exact: MaxResults is honoured, order is
    preserved across page boundaries, and the walk yields every item exactly once."""
    nonce = ctx.unique_name("sim2real-behav-coderepo-")
    names = [f"{nonce}-1", f"{nonce}-2", f"{nonce}-3"]
    # Created out of lexical order so a name-sorted answer cannot be insertion order.
    for name in (names[2], names[0], names[1]):
        _create_code_repository(ctx, name)

    # Unpaginated baseline: the nonce scopes the query to exactly our three.
    # Creation is reflected in List* with a small lag, so poll to a deadline.
    baseline = _poll_until(
        lambda: _pages(ctx, name_contains=nonce, max_results=100),
        lambda res: [n for page in res[0] for n in page] == names,
        timeout_s=60,
        description=f"ListCodeRepositories(NameContains={nonce}) shows all 3 repos",
    )
    assert not baseline[1], f"unpaginated listing did not terminate: {baseline[0]}"
    flat_baseline = [n for page in baseline[0] for n in page]
    assert flat_baseline == names, (
        f"NameContains={nonce} SortBy=Name Ascending returned {flat_baseline}, "
        f"expected {names}"
    )

    pages, exhausted = _pages(ctx, name_contains=nonce, max_results=1)
    assert not exhausted, (
        f"paginated walk did not terminate within the page cap: {pages}"
    )
    for i, page in enumerate(pages):
        assert len(page) <= 1, (
            f"page {i} has {len(page)} items with MaxResults=1: {page} -- "
            f"MaxResults is being ignored"
        )
    non_empty = [page for page in pages if page]
    assert len(non_empty) == 3, (
        f"expected 3 single-item pages, got {len(non_empty)}: {pages}"
    )
    assert len(pages) >= 2, (
        f"a 3-item result with MaxResults=1 must have produced a NextToken: {pages}"
    )

    flat = [n for page in pages for n in page]
    assert len(flat) == len(set(flat)), f"pagination duplicated items: {flat}"
    assert sorted(flat) == names, (
        f"pagination lost or invented items: walked {flat}, created {names}"
    )
    # Ordering must survive the page boundary, not just within a page.
    assert flat == names, (
        f"cross-page order broken: walked {flat}, expected {names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
