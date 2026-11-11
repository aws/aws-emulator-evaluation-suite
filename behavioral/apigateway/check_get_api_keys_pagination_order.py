"""get-api-keys-pagination-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-api-keys-pagination-order"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApiKeys returns keys in a stable, server-defined order across paginated
    requests, and that order is independent of page size."""
    apigw = ctx.client("apigateway")

    base = ctx.unique_name("sim2real-apikey-")
    suffixes = ["zulu", "yankee", "xray", "whiskey", "victor"]
    names = [f"{base}-{s}" for s in suffixes]

    for name in names:
        key_id = apigw.create_api_key(name=name, enabled=False)["id"]
        ctx.on_cleanup(lambda kid=key_id: apigw.delete_api_key(apiKey=kid))

    def _scan_ours(page_limit: int) -> list[str]:
        items: list[dict] = []
        position = None
        for _ in range(50):
            kwargs = {"limit": page_limit, "nameQuery": base}
            if position:
                kwargs["position"] = position
            resp = apigw.get_api_keys(**kwargs)
            items.extend(resp.get("items", []))
            position = resp.get("position")
            if not position:
                break
        else:
            raise AssertionError("pagination did not terminate within 50 pages")
        return [item["name"] for item in items if item["name"] in names]

    # Two independent full paginated scans, at *different* page sizes, so a page-size-
    # dependent reordering cannot hide behind repeating an identical call twice.
    order_a = _scan_ours(page_limit=2)
    order_b = _scan_ours(page_limit=3)

    assert set(order_a) == set(names), (
        f"expected all {len(names)} created keys to appear exactly once via pagination, got {order_a}"
    )
    assert len(order_a) == len(names), f"pagination produced duplicates/skips: {order_a}"
    assert order_b == order_a, (
        f"GetApiKeys pagination order was not stable across page sizes: {order_a} != {order_b}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
