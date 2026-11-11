"""update-api-key-and-list-keys."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-api-key-and-list-keys"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey patches the enabled flag and GetApiKeys reflects it in the
    collection listing."""
    apigw = ctx.client("apigateway")
    key_name = ctx.unique_name("sim2real-apikey-")
    key_id = apigw.create_api_key(
        name=key_name, enabled=True, tags={"sim2real": "update-api-key-and-list-keys"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    before = apigw.get_api_key(apiKey=key_id)
    assert before["enabled"] is True, before

    apigw.update_api_key(
        apiKey=key_id,
        patchOperations=[
            {"op": "replace", "path": "/enabled", "value": "false"},
            {"op": "replace", "path": "/description", "value": "disabled by sim2real"},
        ],
    )

    keys = apigw.get_api_keys(nameQuery=key_name)["items"]
    by_id = {k["id"]: k for k in keys}
    assert key_id in by_id, f"expected {key_id} in GetApiKeys(nameQuery={key_name}), got {list(by_id)}"
    key = by_id[key_id]
    assert key["enabled"] is False, key
    assert key["description"] == "disabled by sim2real", key


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
