"""op-contract-updateApiKey-expires-out-of-bounds-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-updateApiKey-expires-out-of-bounds-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey persists a new description/expiry (visible via ListApiKeys); an expiry more than
    365 days out is rejected with ApiKeyValidityOutOfBoundsException and leaves the key as is."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, appsync)

    now = int(time.time())
    initial_expires = now + 3 * 86400
    created = appsync.create_api_key(apiId=api_id, description="initial", expires=initial_expires)
    key_id = created["apiKey"]["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key_id))

    new_expires = now + 30 * 86400
    updated = appsync.update_api_key(apiId=api_id, id=key_id, description="rotated", expires=new_expires)
    assert updated["apiKey"]["description"] == "rotated", (
        f"expected description 'rotated', got {updated['apiKey']['description']!r}"
    )
    # AppSync rounds expires down to the nearest hour
    assert abs(updated["apiKey"]["expires"] - new_expires) < 3600, (
        f"expected expires near {new_expires}, got {updated['apiKey']['expires']}"
    )

    listed = {k["id"]: k for k in appsync.list_api_keys(apiId=api_id)["apiKeys"]}
    assert listed[key_id]["description"] == "rotated", (
        f"ListApiKeys did not reflect the update: {listed[key_id]!r}"
    )

    too_far = now + 400 * 86400
    code, message = _error(lambda: appsync.update_api_key(apiId=api_id, id=key_id, expires=too_far))
    assert code == "ApiKeyValidityOutOfBoundsException", f"expected ApiKeyValidityOutOfBoundsException, got {code}"
    assert message == "API key can be valid for a maximum of 365 days.", message

    unchanged = {k["id"]: k for k in appsync.list_api_keys(apiId=api_id)["apiKeys"]}
    assert abs(unchanged[key_id]["expires"] - new_expires) < 3600, (
        "rejected UpdateApiKey must not have changed the stored expiry"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected ApiKeyValidityOutOfBoundsException, but the call SUCCEEDED and returned {result!r}"
    )


def _create_graphql_api(ctx, appsync):
    name = ctx.unique_name("sim2real-appsync-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK, "sim2real:managed": "true"}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
