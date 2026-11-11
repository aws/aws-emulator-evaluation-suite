"""get-schema-lifecycle-not-found-then-present."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-schema-lifecycle-not-found-then-present"
GROUP = "state"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSchema on a new policy store returns schema "{}" with no namespaces, and after PutSchema it returns the stored
    schema exactly with namespaces ["PhotoApp"]."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)

    before = client.get_schema(policyStoreId=store_id)
    assert before.get("schema") == "{}", f"expected implicit empty schema '{{}}', got {before.get('schema')!r}"
    assert before.get("namespaces", []) == [], f"expected no namespaces before PutSchema, got {before.get('namespaces')!r}"

    import json

    schema = {
        "PhotoApp": {
            "entityTypes": {"User": {}, "Photo": {}},
            "actions": {
                "viewPhoto": {
                    "appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Photo"]}
                }
            },
        }
    }
    client.put_schema(policyStoreId=store_id, definition={"cedarJson": json.dumps(schema)})

    got = client.get_schema(policyStoreId=store_id)
    assert got["policyStoreId"] == store_id, f"expected policyStoreId {store_id!r}, got {got['policyStoreId']!r}"
    assert got["namespaces"] == ["PhotoApp"], f"expected namespaces ['PhotoApp'], got {got['namespaces']!r}"
    assert json.loads(got["schema"]) == schema, f"expected stored schema to round-trip exactly, got {got['schema']!r}"


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
