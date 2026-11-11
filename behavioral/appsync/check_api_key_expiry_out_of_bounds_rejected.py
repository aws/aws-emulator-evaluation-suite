"""api-key-expiry-out-of-bounds-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "api-key-expiry-out-of-bounds-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiKey rejects an `expires` more than 365 days ahead with
    ApiKeyValidityOutOfBoundsException, while an in-bounds expiry on the same API succeeds and
    shows up in ListApiKeys."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]

    too_far = int(time.time()) + 400 * 86400  # > 365 day maximum validity window

    code, message = _error(lambda: appsync.create_api_key(apiId=api_id, expires=too_far))
    assert code == "ApiKeyValidityOutOfBoundsException", (
        f"expected ApiKeyValidityOutOfBoundsException, got {code}"
    )
    assert message == "API key can be valid for a maximum of 365 days.", (
        f"expected AWS's exact out-of-bounds message, got {message!r}"
    )

    keys = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert keys == [], f"an out-of-bounds key should never have been created: {keys}"

    in_bounds = int(time.time()) + 30 * 86400
    created = appsync.create_api_key(apiId=api_id, expires=in_bounds)["apiKey"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=created["id"]))

    keys_after_control = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert [k["id"] for k in keys_after_control] == [created["id"]], (
        f"expected the in-bounds key alone in ListApiKeys, got {keys_after_control}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
