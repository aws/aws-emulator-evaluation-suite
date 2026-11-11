"""api-key-update-expiry-extends-deletion."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "api-key-update-expiry-extends-deletion"
GROUP = "state"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey with a later `expires` value actually extends the key's real
    expiration (round-tripped through GetApiKey via ListApiKeys), not just the
    field echoed back on the update response."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]

    now_hour = int(time.time() // 3600 * 3600)
    initial_expires = now_hour + 2 * 86400
    extended_expires = now_hour + 10 * 86400
    # Both are already hour-aligned, so AppSync's documented "rounded down to the nearest
    # hour" floor is a no-op here -- the response must equal the input exactly, not just
    # land within an hour of it.

    key = appsync.create_api_key(apiId=api_id, expires=initial_expires)["apiKey"]
    key_id = key["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_key(appsync, api_id, key_id))
    assert key["expires"] == initial_expires, (
        f"CreateApiKey expires drifted: expected {initial_expires}, got {key['expires']}"
    )

    updated = appsync.update_api_key(
        apiId=api_id, id=key_id, expires=extended_expires
    )["apiKey"]
    assert updated["expires"] == extended_expires, (
        f"UpdateApiKey expires drifted: expected {extended_expires}, got {updated['expires']}"
    )
    assert updated["expires"] > initial_expires

    listed = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    match = next(k for k in listed if k["id"] == key_id)
    assert match["expires"] == extended_expires, (
        f"ListApiKeys did not reflect the update: expected {extended_expires}, got {match['expires']} ({match})"
    )


def _best_effort_delete_key(appsync, api_id, key_id):
    try:
        appsync.delete_api_key(apiId=api_id, id=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"), authenticationType=auth_type
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
