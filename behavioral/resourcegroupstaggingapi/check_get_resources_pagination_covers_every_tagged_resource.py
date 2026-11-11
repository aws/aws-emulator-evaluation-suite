"""get-resources-pagination-covers-every-tagged-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-resources-pagination-covers-every-tagged-resource"
GROUP = "data-plane"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paging a tag query with ResourcesPerPage 2 returns each of the five tagged resources exactly
    once over at least three pages and ends with an empty PaginationToken.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-page-")
    per_page = 2
    wanted = 5

    arns = []
    for _ in range(wanted):
        url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
        ctx.on_cleanup(lambda u=url: sqs.delete_queue(QueueUrl=u))
        arns.append(
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        )

    rgt.tag_resources(ResourceARNList=arns, Tags={key: "paged"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=arns, TagKeys=[key]))

    # The index must hold all five before paging means anything: a short page set caused by a
    # lagging index would otherwise read as a pagination defect.
    settled = _poll_until(
        lambda: _all_resources(rgt, TagFilters=[{"Key": key}]),
        lambda mappings: len({m["ResourceARN"] for m in mappings}) == wanted,
        timeout_s=180.0,
    )
    assert len({m["ResourceARN"] for m in settled}) == wanted, (
        f"only {len({m['ResourceARN'] for m in settled})} of {wanted} queues reached the tag index "
        f"under {key!r}: {sorted(m['ResourceARN'] for m in settled)!r}"
    )

    pages, token, guard = [], "", 0
    while True:
        guard += 1
        assert guard <= wanted + 3, (
            f"pagination did not terminate after {guard} pages for {wanted} resources; page sizes "
            f"so far {[len(p) for p in pages]!r}"
        )
        kwargs = {"TagFilters": [{"Key": key}], "ResourcesPerPage": per_page}
        if token:
            kwargs["PaginationToken"] = token
        page = rgt.get_resources(**kwargs)
        pages.append([m["ResourceARN"] for m in page["ResourceTagMappingList"]])
        token = page["PaginationToken"]
        if not token:
            break

    sizes = [len(p) for p in pages]
    assert all(size <= per_page for size in sizes), (
        f"a page exceeded ResourcesPerPage={per_page}: page sizes were {sizes!r}"
    )
    # ceil(5/2) pages is the floor implied by the page-size cap; fewer means a page over-ran it.
    assert len(pages) >= -(-wanted // per_page), (
        f"{wanted} resources at {per_page} per page came back in {len(pages)} pages "
        f"(sizes {sizes!r}); at least {-(-wanted // per_page)} are required"
    )

    flat = [arn for page in pages for arn in page]
    assert len(flat) == len(set(flat)), (
        f"pagination returned a duplicate: {sorted(flat)!r}"
    )
    assert set(flat) == set(arns), (
        f"the pages covered {sorted(set(flat))!r}, expected exactly the {wanted} tagged queues "
        f"{sorted(arns)!r}"
    )
    assert token == "", (
        f"the final page's PaginationToken was {token!r}, expected the empty string that ends the walk"
    )


def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
