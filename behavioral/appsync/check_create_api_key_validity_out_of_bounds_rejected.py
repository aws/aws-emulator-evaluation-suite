"""create-api-key-validity-out-of-bounds-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-key-validity-out-of-bounds-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiKey rejects an `expires` value more than 365 days out with ApiKeyValidityOutOfBoundsException,
    and no key is created as a side effect of the rejected call; a well-formed request (30 days out) on the
    same API still succeeds and is visible via an independent ListApiKeys read."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    too_far = int(time.time()) + 400 * 24 * 3600  # ~400 days out; max allowed is 365 days
    code, message = _error(
        lambda: appsync.create_api_key(apiId=api_id, description="out-of-bounds", expires=too_far)
    )
    assert code == "ApiKeyValidityOutOfBoundsException", f"expected ApiKeyValidityOutOfBoundsException, got {code}"
    assert message == "API key can be valid for a maximum of 365 days.", (
        f"expected the exact maximum-validity message, got {message!r}"
    )

    keys_after_rejection = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert keys_after_rejection == [], f"rejected call must not create a key: {keys_after_rejection}"

    # positive control: an in-bounds expiry (30 days) is accepted, proving the rejection is about the value, not the shape
    in_bounds = int(time.time()) + 30 * 24 * 3600
    created = appsync.create_api_key(apiId=api_id, description="in-bounds", expires=in_bounds)[
        "apiKey"
    ]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=created["id"]))

    keys_after_control = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert [k["id"] for k in keys_after_control] == [created["id"]], (
        f"expected the in-bounds key to appear via an independent ListApiKeys read, got {keys_after_control}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    api = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
