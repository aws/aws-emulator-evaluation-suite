"""import-api-keys-bulk-then-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "import-api-keys-bulk-then-list"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportApiKeys bulk-creates a key from CSV that is visible via GetApiKeys
    and, since the CSV names a usage plan, associable via GetUsagePlanKeys."""
    apigw = ctx.client("apigateway")
    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-importplan-"),
        tags={"sim2real-env": "import-api-keys-bulk-then-list"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key_name = ctx.unique_name("sim2real-importedkey-")
    key_value = _alnum_key_value(key_name)
    csv_body = (
        "Name,key,description,Enabled,usageplanIds\n"
        f"{key_name},{key_value},imported by sim2real,TRUE,{plan_id}\n"
    )

    result = apigw.import_api_keys(body=csv_body.encode("utf-8"), format="csv", failOnWarnings=True)
    ids = result["ids"]
    assert len(ids) == 1, f"expected exactly one imported key id, got {ids}"
    key_id = ids[0]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    apigw.tag_resource(
        resourceArn=f"arn:aws:apigateway:{ctx.region}::/apikeys/{key_id}",
        tags={"sim2real-env": "import-api-keys-bulk-then-list"},
    )

    fetched = apigw.get_api_key(apiKey=key_id)
    assert fetched["name"] == key_name, f"expected imported key name {key_name!r}, got {fetched['name']!r}"
    assert fetched["enabled"] is True, f"expected imported key to be enabled, got enabled={fetched['enabled']!r}"

    keys = apigw.get_api_keys(nameQuery=key_name)["items"]
    assert any(k["id"] == key_id for k in keys), f"expected {key_id} in GetApiKeys, got {[k['id'] for k in keys]}"

    plan_keys = apigw.get_usage_plan_keys(usagePlanId=plan_id)["items"]
    assert any(k["id"] == key_id for k in plan_keys), (
        f"expected imported key {key_id} auto-associated with usage plan {plan_id} via usageplanIds column, "
        f"got {[k['id'] for k in plan_keys]}"
    )


def _alnum_key_value(seed: str) -> str:
    raw = "".join(ch for ch in seed if ch.isalnum())
    if len(raw) < 20:
        raw = (raw + "0123456789abcdef0123456789")[:20]
    return raw[:128]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
