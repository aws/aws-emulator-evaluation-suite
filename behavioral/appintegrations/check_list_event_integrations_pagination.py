"""list-event-integrations-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-event-integrations-pagination"
GROUP = "data-plane"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEventIntegrations with a small MaxResults paginates via NextToken, honoring the per-page cap, to cover all created integrations."""
    appi = ctx.client("appintegrations")
    names = [ctx.unique_name(f"sim2real-evt-page{i}-") for i in range(3)]
    for name in names:
        appi.create_event_integration(
            Name=name,
            EventFilter={"Source": "aws.cases"},
            EventBridgeBus="default",
            Tags={"sim2real": CHECK},
        )
        ctx.on_cleanup(lambda n=name: appi.delete_event_integration(Name=n))

    seen: set[str] = set()
    next_token = None
    pages = 0
    page_sizes: list[int] = []
    while pages < 50:
        pages += 1
        kwargs = {"MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = appi.list_event_integrations(**kwargs)
        items = resp["EventIntegrations"]
        page_sizes.append(len(items))
        for item in items:
            seen.add(item["Name"])
        next_token = resp.get("NextToken")
        if not next_token:
            break

    for name in names:
        assert name in seen, f"{name} missing from paginated ListEventIntegrations results"

    for i, size in enumerate(page_sizes):
        assert size <= 1, f"page {i} returned {size} items, exceeding requested MaxResults=1"

    assert pages >= len(names), (
        f"expected at least {len(names)} pages to cover {len(names)} integrations under "
        f"MaxResults=1, got {pages} page(s) — a target that ignores MaxResults and returns "
        f"everything on the first page would pass without this bound"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
