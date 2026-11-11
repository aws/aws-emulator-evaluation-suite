"""api-key-validity-out-of-bounds-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "api-key-validity-out-of-bounds-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiKey with `expires` outside the documented 1-365 day window is rejected with
    ApiKeyValidityOutOfBoundsException and creates no key, while a key 30 days out succeeds and
    shows up in ListApiKeys."""
    appsync = ctx.client("appsync")

    api_name = ctx.unique_name("sim2real-keyapi-")
    api = appsync.create_graphql_api(
        name=api_name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    too_far_expires = int(time.time()) + 400 * 24 * 60 * 60  # 400 days out, over the 365-day ceiling
    code, message = _error(
        lambda: appsync.create_api_key(
            apiId=api_id, description="should-be-rejected", expires=too_far_expires
        )
    )
    assert code == "ApiKeyValidityOutOfBoundsException", (
        f"expected ApiKeyValidityOutOfBoundsException, got {code}"
    )
    assert message == "API key can be valid for a maximum of 365 days.", (
        f"expected AWS's exact out-of-bounds message, got {message!r}"
    )

    keys_after_rejection = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert keys_after_rejection == [], (
        f"expected no api keys after the rejected call, got {keys_after_rejection}"
    )

    valid_expires = int(time.time()) + 30 * 24 * 60 * 60
    created = appsync.create_api_key(apiId=api_id, description="valid-key", expires=valid_expires)["apiKey"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=created["id"]))

    keys_after_control = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert [k["id"] for k in keys_after_control] == [created["id"]], (
        f"expected only {created['id']} in ListApiKeys after the valid create, got {keys_after_control}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so
    accepting input AWS refuses never reads as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected ApiKeyValidityOutOfBoundsException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
