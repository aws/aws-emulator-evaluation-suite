"""list-baselines-pagination-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-baselines-pagination-consistency"
GROUP = "catalog"
SERVICES = ["controltower"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListBaselines with a small page size and following nextToken yields the
    exact same set of baseline ARNs as a single unpaginated call, with no duplicates and
    no drops (the AWS-managed baseline catalog is stable within a single test run)."""
    ct = ctx.client("controltower")

    full_resp = ct.list_baselines(maxResults=100)
    full = full_resp["baselines"]
    assert not full_resp.get("nextToken"), (
        "maxResults=100 call itself paginated — the 'full' listing is incomplete, "
        "so it can no longer serve as the pagination oracle"
    )
    assert len(full) >= 4, "need at least 4 baselines to exercise a small page size (min maxResults=4)"
    full_arns = sorted(b["arn"] for b in full)

    paged_arns: list[str] = []
    kwargs = {"maxResults": 4}
    for _ in range(50):  # hard bound so a buggy emulator can't loop forever
        page = ct.list_baselines(**kwargs)
        paged_arns.extend(b["arn"] for b in page["baselines"])
        next_token = page.get("nextToken")
        if not next_token:
            break
        kwargs = {"maxResults": 4, "nextToken": next_token}
    else:
        raise AssertionError("pagination did not terminate within 50 pages")

    assert sorted(paged_arns) == full_arns, "paginated ARNs differ from the unpaginated listing"
    assert len(paged_arns) == len(set(paged_arns)), "pagination returned duplicate baselines"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
