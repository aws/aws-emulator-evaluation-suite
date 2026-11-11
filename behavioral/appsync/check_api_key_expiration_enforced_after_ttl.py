"""api-key-expiration-enforced-after-ttl."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-key-expiration-enforced-after-ttl"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]

_DAY = 86400
_HOUR = 3600


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey enforces the 1-365 day expiry window (rejecting near-term values),
    UpdateApiKey can extend a key's expiry within that window, and a rejected update
    leaves the stored expiry untouched."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    now = int(time.time())

    # --- negative: an expires timestamp under the 1-day minimum is rejected, and no key
    # is left behind.
    too_soon = now + 2 * _HOUR
    code, message = _error(lambda: appsync.create_api_key(apiId=api_id, expires=too_soon))
    assert code == "ApiKeyValidityOutOfBoundsException", (
        f"expected ApiKeyValidityOutOfBoundsException for a sub-1-day expires, got {code!r}"
    )
    assert message == "API key must be valid for a minimum of 1 days.", message
    keys_after_rejection = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert keys_after_rejection == [], (
        f"expected no api keys after the rejected create, got {keys_after_rejection}"
    )

    # --- positive control: 2 days out is within [1, 365] days and succeeds.
    valid_expires = now + 2 * _DAY
    created = appsync.create_api_key(apiId=api_id, description="ttl-check", expires=valid_expires)
    key_id = created["apiKey"]["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key_id))
    first_expires = created["apiKey"]["expires"]
    # AppSync floors expires to the hour.
    expected_first = valid_expires - (valid_expires % _HOUR)
    assert first_expires == expected_first, (
        f"expected {expected_first} (valid_expires floored to the hour), got {first_expires}"
    )
    stored_first = _stored_expires(appsync, api_id, key_id)
    assert stored_first == first_expires, (
        f"ListApiKeys expires {stored_first} does not match CreateApiKey's own {first_expires}"
    )

    # --- UpdateApiKey extends expiry within bounds.
    extended_expires = now + 10 * _DAY
    updated = appsync.update_api_key(apiId=api_id, id=key_id, expires=extended_expires)
    second_expires = updated["apiKey"]["expires"]
    expected_second = extended_expires - (extended_expires % _HOUR)
    assert second_expires == expected_second, (
        f"expected {expected_second} (extended_expires floored to the hour), got {second_expires}"
    )
    assert second_expires > first_expires, (
        f"expected the extension to raise expires past {first_expires}, got {second_expires}"
    )
    stored_second = _stored_expires(appsync, api_id, key_id)
    assert stored_second == second_expires, (
        f"ListApiKeys expires {stored_second} does not match UpdateApiKey's own {second_expires}"
    )

    # --- negative: extending beyond 365 days is rejected and the stored expiry is unchanged.
    too_far = now + 400 * _DAY
    code, message = _error(lambda: appsync.update_api_key(apiId=api_id, id=key_id, expires=too_far))
    assert code == "ApiKeyValidityOutOfBoundsException", (
        f"expected ApiKeyValidityOutOfBoundsException for an out-of-bounds update, got {code!r}"
    )
    assert message == "API key can be valid for a maximum of 365 days.", message
    unchanged = _stored_expires(appsync, api_id, key_id)
    assert unchanged == second_expires, (
        f"rejected UpdateApiKey must not have changed the stored expiry: "
        f"expected {second_expires}, got {unchanged}"
    )


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _stored_expires(appsync, api_id: str, key_id: str) -> int:
    for key in appsync.list_api_keys(apiId=api_id)["apiKeys"]:
        if key["id"] == key_id:
            return key["expires"]
    raise AssertionError(f"api key {key_id} not found in ListApiKeys")


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
