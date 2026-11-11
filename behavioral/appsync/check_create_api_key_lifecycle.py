"""create-api-key-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-api-key-lifecycle"
GROUP = 'api-key'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey -> ListApiKeys shows it -> DeleteApiKey -> ListApiKeys no longer shows it."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY")["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    now = int(time.time())
    expires = now + 2 * 24 * 3600  # 2 days out, inside the 1-365 day window

    created = svc.create_api_key(apiId=api_id, description="fidelity-key", expires=expires)["apiKey"]
    key_id = created["id"]
    assert created["description"] == "fidelity-key", (
        f"expected description 'fidelity-key', got {created['description']!r}"
    )
    # Real AppSync does not store the requested epoch verbatim: it floors the
    # expiration to the nearest hour boundary. Assert that exact rounding.
    assert created["expires"] == expires - (expires % 3600), (
        f"expected hour-floored {expires - (expires % 3600)}, got {created['expires']}"
    )

    ids = [k["id"] for k in svc.list_api_keys(apiId=api_id)["apiKeys"]]
    assert key_id in ids, f"expected {key_id} in ListApiKeys result {ids}"

    svc.delete_api_key(apiId=api_id, id=key_id)

    ids_after = [k["id"] for k in svc.list_api_keys(apiId=api_id)["apiKeys"]]
    assert key_id not in ids_after, f"expected {key_id} absent from ListApiKeys, still present in {ids_after}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
