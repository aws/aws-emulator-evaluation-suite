"""get-api-keys-list-pagination-order-stable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-api-keys-list-pagination-order-stable"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApiKeys paginated listing returns keys in stable creation order across pages."""
    apigw = ctx.client("apigateway")
    base = ctx.unique_name("sim2real-apikey-")

    created_ids: list[str] = []
    for i in range(5):
        resp = apigw.create_api_key(
            name=f"{base}-{i}", enabled=True, tags={"sim2real": "get-api-keys-pagination-order-stable"}
        )
        created_ids.append(resp["id"])
        ctx.on_cleanup(lambda kid=resp["id"]: apigw.delete_api_key(apiKey=kid))
        time.sleep(0.2)  # ensure distinguishable createdDate ordering

    def _collect_all_ids(page_limit: int) -> list[str]:
        ids: list[str] = []
        position = None
        while True:
            kwargs = {"limit": page_limit, "nameQuery": base}
            if position:
                kwargs["position"] = position
            resp = apigw.get_api_keys(**kwargs)
            ids.extend(item["id"] for item in resp.get("items", []))
            position = resp.get("position")
            if not position:
                break
        return ids

    pass_1 = _collect_all_ids(2)
    pass_2 = _collect_all_ids(2)

    assert pass_1 == created_ids, f"expected creation order {created_ids}, got {pass_1}"
    assert pass_2 == pass_1, f"pagination order not stable across calls: {pass_1} vs {pass_2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
