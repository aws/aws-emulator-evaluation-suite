"""list-services-pagination-no-duplicates-or-gaps."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-services-pagination-no-duplicates-or-gaps"
GROUP = "list"
SERVICES = ["uxc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListServices with a small page size yields every service identifier exactly
    once, with no duplicates and no gaps relative to the same catalog fetched with the largest
    permitted page size."""
    uxc = ctx.client("uxc")

    collected = _collect(uxc, page_size=5, max_pages=200)
    assert len(collected) >= 1
    assert len(collected) == len(set(collected)), "duplicate service identifiers across pages"

    # Independent reference: the same catalog paginated with the largest permitted page size
    # (model max 1000; ServiceList max length 500, so this is at most two pages). If the small
    # page size silently dropped an identifier at a page boundary, the two sets diverge.
    reference = _collect(uxc, page_size=1000, max_pages=200)
    assert len(reference) == len(set(reference)), "duplicate service identifiers within the reference fetch"
    missing = set(reference) - set(collected)
    extra = set(collected) - set(reference)
    assert not missing and not extra, (
        f"small-page pagination diverged from the large-page reference fetch: "
        f"missing={sorted(missing)!r} extra={sorted(extra)!r}"
    )


def _collect(uxc, page_size: int, max_pages: int) -> list[str]:
    collected: list[str] = []
    next_token = None
    pages = 0
    while pages < max_pages:
        kwargs = {"maxResults": page_size}
        if next_token:
            kwargs["nextToken"] = next_token
        page = uxc.list_services(**kwargs)
        collected.extend(page["services"])
        next_token = page.get("nextToken")
        pages += 1
        if not next_token:
            break
    else:
        raise AssertionError("ListServices pagination did not terminate within the page budget")
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
