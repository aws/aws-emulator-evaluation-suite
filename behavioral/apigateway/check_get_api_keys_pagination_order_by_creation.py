"""get-api-keys-pagination-order-by-creation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-api-keys-pagination-order-by-creation"
GROUP = "ordering"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApiKeys returns a caller's keys in a stable order (server-defined, not necessarily
    creation order) that is reproduced identically across two independent full paginated scans
    using different page sizes, with every created key present exactly once."""
    apigw = ctx.client("apigateway")

    base = ctx.unique_name("sim2real-apikeys-order")
    created_ids: list[str] = []
    ctx.on_cleanup(lambda: [apigw.delete_api_key(apiKey=kid) for kid in created_ids])
    for i in range(5):
        resp = apigw.create_api_key(
            name=f"{base}-{i}",
            enabled=True,
            tags={"sim2real": CHECK},
        )
        created_ids.append(resp["id"])

    pass_one = _ordered_ids_for_prefix(apigw, base, page_size=2)
    pass_two = _ordered_ids_for_prefix(apigw, base, page_size=4)

    assert sorted(pass_one) == sorted(created_ids), (
        f"first paginated scan {sorted(pass_one)} does not contain exactly the created keys "
        f"{sorted(created_ids)}"
    )
    assert pass_two == pass_one, (
        f"second paginated scan (different page size) returned a different order: "
        f"{pass_two} vs {pass_one}"
    )


def _ordered_ids_for_prefix(apigw, base: str, page_size: int) -> list[str]:
    ids: list[str] = []
    position = None
    for _ in range(200):
        kwargs = {"limit": page_size, "nameQuery": base}
        if position:
            kwargs["position"] = position
        resp = apigw.get_api_keys(**kwargs)
        for item in resp.get("items", []):
            if item.get("name", "").startswith(base):
                ids.append(item["id"])
        position = resp.get("position")
        if not position:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
