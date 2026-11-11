"""list-pull-time-update-exclusions-pagination-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-pull-time-update-exclusions-pagination-order"
GROUP = "ordering"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-pull-time-exclusions")
def run(ctx) -> None:
    """ListPullTimeUpdateExclusions returns the same exclusions, each once, whether fetched as
    one unpaginated page or walked page-by-page with a small maxResults, and across repeated
    full listings; AWS documents no order, so the listings are compared order-insensitively."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    arns = []
    for i in range(5):
        name = ctx.unique_name(f"sim2real-behav-excl-order-{i}-")
        arn = f"arn:aws:iam::{account}:role/{name}"
        ecr.register_pull_time_update_exclusion(principalArn=arn)
        ctx.on_cleanup(
            lambda a=arn: ecr.deregister_pull_time_update_exclusion(principalArn=a)
        )
        arns.append(arn)

    full = _list_all(ecr, page_size=1000)
    paged, page_count = _list_all_with_pages(ecr, page_size=2)

    # 5 freshly-registered items with maxResults=2 must span at least 3 pages.
    assert page_count >= 3, f"expected >=3 pages with maxResults=2, got {page_count}"

    full_ours = [a for a in full if a in arns]
    paged_ours = [a for a in paged if a in arns]
    assert set(full_ours) == set(arns), (
        f"expected all {len(arns)} registered exclusions in the unpaginated listing, "
        f"got {full_ours}"
    )
    assert full_ours == paged_ours or sorted(full_ours) == sorted(paged_ours), (
        "pagination must return the same exclusions, each once, as an unpaginated listing: "
        f"{full_ours} vs {paged_ours}"
    )

    again_ours = [a for a in _list_all(ecr, page_size=1000) if a in arns]
    assert again_ours == full_ours or sorted(again_ours) == sorted(full_ours), (
        f"ListPullTimeUpdateExclusions must return the same exclusions across repeated calls: "
        f"{full_ours} vs {again_ours}"
    )


def _list_all(ecr, page_size: int) -> list[str]:
    out: list[str] = []
    token = None
    while True:
        kwargs = {"maxResults": page_size}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        out.extend(resp.get("pullTimeUpdateExclusions", []))
        token = resp.get("nextToken")
        if not token:
            return out


def _list_all_with_pages(ecr, page_size: int) -> tuple[list[str], int]:
    out: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"maxResults": page_size}
        if token:
            kwargs["nextToken"] = token
        resp = ecr.list_pull_time_update_exclusions(**kwargs)
        out.extend(resp.get("pullTimeUpdateExclusions", []))
        pages += 1
        token = resp.get("nextToken")
        if not token:
            return out, pages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
