"""list-types-stable-ordering-across-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-types-stable-ordering-across-pagination"
GROUP = "ordering"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTypes paginated via NextToken over the (large, stable) set of AWS-published public
    types returns a total ordering with no duplicate or skipped entries across pages, and
    that ordering is identical across two independent full traversals."""
    first_pass, first_pages = _paginate_type_arns(ctx)
    assert len(first_pass) > 20, (
        f"expected a sizeable AWS_TYPES catalog to paginate over, only saw {len(first_pass)}"
    )
    assert first_pages > 1, (
        f"expected MaxResults=20 to force multiple ListTypes pages for >20 results, "
        f"only saw {first_pages} page(s) -- NextToken pagination was never exercised"
    )
    assert len(first_pass) == len(set(first_pass)), "duplicate TypeArn seen across pages"

    second_pass, second_pages = _paginate_type_arns(ctx)
    assert second_pass == first_pass, "ListTypes pagination order was not stable across traversals"
    assert second_pages == first_pages, (
        f"expected the second traversal to page the same way as the first, "
        f"got {second_pages} pages vs {first_pages}"
    )


def _paginate_type_arns(ctx, page_size=20, max_pages=30):
    cfn = ctx.client("cloudformation")
    arns = []
    next_token = None
    pages = 0
    while pages < max_pages:
        kwargs = {
            "Visibility": "PUBLIC",
            "Filters": {"Category": "AWS_TYPES"},
            "MaxResults": page_size,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cfn.list_types(**kwargs)
        arns.extend(t["TypeArn"] for t in resp.get("TypeSummaries", []))
        next_token = resp.get("NextToken")
        pages += 1
        if not next_token:
            break
    return arns, pages


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
