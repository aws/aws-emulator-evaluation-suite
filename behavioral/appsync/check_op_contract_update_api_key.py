"""op-contract-updateApiKey."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-updateApiKey"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey changes description/expires visible via ListApiKeys; expires out of the 1-365 day window is rejected."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    now = int(time.time())
    key = appsync.create_api_key(
        apiId=api_id, description="initial", expires=now + 5 * 86400
    )["apiKey"]
    key_id = key["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key_id))

    new_expires = now + 20 * 86400
    appsync.update_api_key(
        apiId=api_id, id=key_id, description="updated", expires=new_expires
    )

    keys = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    updated = next(k for k in keys if k["id"] == key_id)
    assert updated["description"] == "updated", f"expected description 'updated', got {updated}"
    # AppSync may round expires down to a day boundary; allow small slack.
    assert abs(updated["expires"] - new_expires) < 90000, (
        f"expected expires near {new_expires}, got {updated['expires']}"
    )

    code, message = _error(
        lambda: appsync.update_api_key(
            apiId=api_id, id=key_id, expires=now + 400 * 86400
        )
    )
    assert code == "ApiKeyValidityOutOfBoundsException", (
        f"expected ApiKeyValidityOutOfBoundsException for a >365-day expiry, got {code}"
    )
    assert message == "API key can be valid for a maximum of 365 days.", message

    # The rejected call must not have moved the state the earlier positive control set.
    after = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    unchanged = next(k for k in after if k["id"] == key_id)
    assert unchanged["description"] == "updated", (
        f"a rejected UpdateApiKey must not change the description: {unchanged}"
    )
    assert abs(unchanged["expires"] - new_expires) < 90000, (
        f"a rejected UpdateApiKey must not change the expiry: {unchanged}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
