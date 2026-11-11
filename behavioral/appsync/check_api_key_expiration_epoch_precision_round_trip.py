"""api-key-expiration-epoch-precision-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "api-key-expiration-epoch-precision-round-trip"
GROUP = "api-key"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An API key created with an hour-aligned epoch expiration returns that exact integer."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    # AWS documents `expires` (CreateApiKey) as "seconds since the epoch, rounded down to
    # the nearest hour". We pick a value already aligned to an hour boundary, ~10 days out
    # (within the 1-365 day validity window), so the documented rounding is a no-op and the
    # response value must equal the input exactly -- no further rounding, no timezone drift.
    now = int(time.time())
    ten_days_out = now + 10 * 24 * 3600
    expires = (ten_days_out // 3600) * 3600

    create_resp = appsync.create_api_key(
        apiId=api_id, description="epoch-precision-check", expires=expires
    )
    key_id = create_resp["apiKey"]["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key_id))

    assert create_resp["apiKey"]["expires"] == expires, (
        f"CreateApiKey response expires drifted: {create_resp['apiKey']['expires']} != {expires}"
    )

    list_resp = appsync.list_api_keys(apiId=api_id)
    matches = [k for k in list_resp["apiKeys"] if k["id"] == key_id]
    assert len(matches) == 1, f"expected exactly one matching api key, found {len(matches)}"
    assert matches[0]["expires"] == expires, (
        f"ListApiKeys expires drifted: {matches[0]['expires']} != {expires}"
    )


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
