"""update-api-key-patch-enabled."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-api-key-patch-enabled"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey toggles the enabled flag independently of value/name."""
    apigw = ctx.client("apigateway")

    key_name = ctx.unique_name("sim2real-bh-key-")
    created = apigw.create_api_key(
        name=key_name,
        enabled=True,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    key_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    original_value = created["value"]
    assert created["enabled"] is True, f"expected newly created key enabled=True, got {created['enabled']!r}"

    updated = apigw.update_api_key(
        apiKey=key_id,
        patchOperations=[{"op": "replace", "path": "/enabled", "value": "false"}],
    )
    assert updated["enabled"] is False, f"expected enabled=False after patch, got {updated['enabled']!r}"
    assert updated["name"] == key_name, "UpdateApiKey must not change name"
    # UpdateApiKey's response (like GetApiKey without includeValue=True) does not echo the
    # secret value back; the invariant we actually care about -- that patching /enabled
    # leaves the key's value untouched -- is verified via GetApiKey(includeValue=True) below.

    fetched = apigw.get_api_key(apiKey=key_id, includeValue=True)
    assert fetched["enabled"] is False, f"expected enabled=False on independent read, got {fetched['enabled']!r}"
    assert fetched["name"] == key_name, f"expected name={key_name!r} unchanged, got {fetched['name']!r}"
    assert fetched["value"] == original_value, (
        f"patching /enabled must not change the key value: expected {original_value!r}, "
        f"got {fetched['value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
