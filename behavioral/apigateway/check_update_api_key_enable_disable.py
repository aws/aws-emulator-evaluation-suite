"""update-api-key-enable-disable."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-api-key-enable-disable"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Patching an api key's enabled flag to false disables it without deleting it: the key
    still appears in GetApiKeys with enabled=False, while a sibling key left untouched stays
    enabled=True (positive control)."""
    apigw = ctx.client("apigateway")

    key_to_disable_name = ctx.unique_name("sim2real-apikey-disable-")
    key_control_name = ctx.unique_name("sim2real-apikey-control-")

    key_to_disable = apigw.create_api_key(
        name=key_to_disable_name, enabled=True, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_to_disable["id"]))
    key_control = apigw.create_api_key(
        name=key_control_name, enabled=True, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_control["id"]))

    assert key_to_disable["enabled"] is True, "freshly created key must start enabled"

    apigw.update_api_key(
        apiKey=key_to_disable["id"],
        patchOperations=[{"op": "replace", "path": "/enabled", "value": "false"}],
    )

    listed = _list_all_api_keys(apigw)
    disabled_item = next(k for k in listed if k["id"] == key_to_disable["id"])
    control_item = next(k for k in listed if k["id"] == key_control["id"])

    assert disabled_item["enabled"] is False, "disabled key must show enabled=False in GetApiKeys"
    assert disabled_item["name"] == key_to_disable_name, "id/name must be unchanged, not deleted"
    assert control_item["enabled"] is True, "untouched sibling key must remain enabled"


def _list_all_api_keys(apigw):
    items = []
    position = None
    for _ in range(10):
        kwargs = {"limit": 500}
        if position:
            kwargs["position"] = position
        page = apigw.get_api_keys(**kwargs)
        items.extend(page.get("items", []))
        position = page.get("position")
        if not position:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
