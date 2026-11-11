"""list-control-mappings-pagination-stitches-consistently."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-control-mappings-pagination-stitches-consistently"
GROUP = "pagination"
SERVICES = ["controlcatalog"]

_SPAN = 5


def _key(m):
    return (m["ControlArn"], m["MappingType"])


def _drain(cc, max_results, limit):
    items = []
    page_sizes = []
    token = None
    saw_next_token = False
    while len(items) < limit:
        kwargs = {"MaxResults": max_results}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_control_mappings(**kwargs)
        page_sizes.append(len(page["ControlMappings"]))
        items.extend(page["ControlMappings"])
        token = page.get("NextToken")
        if token:
            saw_next_token = True
        else:
            break
    return items[:limit], saw_next_token, page_sizes


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Draining the same span of ListControlMappings with MaxResults=1 (pages of at most one item, with a
    NextToken) and with a larger MaxResults yields the same ordered mappings: AWS may return pages smaller
    than MaxResults, so pagination is correct by stitching order, not page size."""
    cc = ctx.client("controlcatalog")

    coarse, _, _ = _drain(cc, 100, _SPAN)
    assert len(coarse) == _SPAN, (
        f"expected at least {_SPAN} control mappings in this account/region, got {len(coarse)}"
    )

    fine, saw_next_token, fine_sizes = _drain(cc, 1, _SPAN)
    assert len(fine) == _SPAN, f"single-item-page drain did not reach {_SPAN} items, got {len(fine)}"
    assert saw_next_token, (
        "expected at least one NextToken while draining one mapping at a time over a "
        f"{_SPAN}-item span"
    )
    assert all(sz <= 1 for sz in fine_sizes), (
        f"MaxResults=1 returned a page larger than 1 item: page sizes {fine_sizes}"
    )

    coarse_keys = [_key(m) for m in coarse]
    fine_keys = [_key(m) for m in fine]
    assert fine_keys == coarse_keys, (
        f"paginated stitching {fine_keys} did not match the coarser-paginated listing {coarse_keys}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
