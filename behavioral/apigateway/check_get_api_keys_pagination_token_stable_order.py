"""get-api-keys-pagination-token-stable-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-api-keys-pagination-token-stable-order"
GROUP = "ordering"
SERVICES = ["apigateway"]

_KEY_COUNT = 7


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApiKeys pagination returns every created key exactly once (no duplicates or gaps), and
    walks with page sizes 3 and 2 produce the identical ordering."""
    apigw = ctx.client("apigateway")
    prefix = ctx.unique_name("sim2real-behav-key-")
    created_ids = []
    for i in range(_KEY_COUNT):
        resp = apigw.create_api_key(
            name=f"{prefix}{i}",
            enabled=False,
            tags={"sim2real": "get-api-keys-pagination-token-stable-order"},
        )
        created_ids.append(resp["id"])
        ctx.on_cleanup(lambda kid=resp["id"]: apigw.delete_api_key(apiKey=kid))

    def _list_all_paginated(limit: int) -> list[str]:
        ids: list[str] = []
        seen: set[str] = set()
        position = None
        while True:
            kwargs = {"nameQuery": prefix, "limit": limit}
            if position:
                kwargs["position"] = position
            page = apigw.get_api_keys(**kwargs)
            for item in page["items"]:
                assert item["id"] not in seen, (
                    f"GetApiKeys pagination returned duplicate id {item['id']} "
                    f"(page size {limit})"
                )
                seen.add(item["id"])
                ids.append(item["id"])
            position = page.get("position")
            if not position:
                break
            # guard against pagination that never terminates
            assert len(ids) <= _KEY_COUNT + 5, f"pagination did not terminate: {ids}"
        return ids

    paged_small = _list_all_paginated(3)
    assert sorted(paged_small) == sorted(created_ids), (
        f"paginated listing (limit=3) did not return exactly the created keys: "
        f"{paged_small} vs {created_ids}"
    )

    paged_other = _list_all_paginated(2)
    assert paged_small == paged_other, (
        f"GetApiKeys produced a different ordering when paginated with a different "
        f"page size: {paged_small} vs {paged_other}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
