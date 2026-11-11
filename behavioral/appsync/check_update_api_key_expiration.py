"""update-api-key-expiration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-api-key-expiration"
GROUP = 'api-key'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey changes the expires timestamp and it is reflected in ListApiKeys."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    now = int(time.time())
    original_expires = now + 2 * 24 * 3600
    new_expires = now + 10 * 24 * 3600

    created = svc.create_api_key(apiId=api_id, expires=original_expires)["apiKey"]
    key_id = created["id"]

    updated = svc.update_api_key(apiId=api_id, id=key_id, expires=new_expires)["apiKey"]
    expected = new_expires - (new_expires % 3600)  # AppSync floors to the hour
    assert updated["expires"] == expected, f"expected {expected}, got {updated['expires']}"

    listed = {k["id"]: k for k in svc.list_api_keys(apiId=api_id)["apiKeys"]}
    assert listed[key_id]["expires"] == expected, (
        f"ListApiKeys did not reflect the update: expected expires {expected}, got {listed.get(key_id)}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
