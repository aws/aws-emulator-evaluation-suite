"""update-api-key-validity-out-of-bounds-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-api-key-validity-out-of-bounds-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey with expires > 365 days out is rejected with ApiKeyValidityOutOfBoundsException,
    the key's stored expiry is untouched by the rejected call, and a well-formed update to the same
    key still succeeds -- proving the API is not simply refusing every UpdateApiKey call."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx, appsync)

    key = appsync.create_api_key(apiId=api["apiId"], description="sim2real-behav-key")["apiKey"]
    key_id = key["id"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api["apiId"], id=key_id))

    now = int(time.time())

    # Positive control: an in-bounds update succeeds and is reflected in an independent read.
    in_bounds_expires = now + 30 * 24 * 3600
    updated = appsync.update_api_key(apiId=api["apiId"], id=key_id, expires=in_bounds_expires)["apiKey"]
    assert abs(updated["expires"] - in_bounds_expires) < 3600, (
        f"in-bounds UpdateApiKey should have set expires near {in_bounds_expires}, got {updated['expires']}"
    )
    listed = {k["id"]: k for k in appsync.list_api_keys(apiId=api["apiId"])["apiKeys"]}
    control_expires = listed[key_id]["expires"]
    assert abs(control_expires - in_bounds_expires) < 3600, (
        f"the positive control's new expiry did not persist: expected near {in_bounds_expires}, "
        f"got {control_expires}"
    )

    too_far_future = now + 400 * 24 * 3600  # > 365 days, out of bounds

    code, msg = _error(
        lambda: appsync.update_api_key(
            apiId=api["apiId"], id=key_id, expires=too_far_future
        )
    )
    assert code == "ApiKeyValidityOutOfBoundsException", f"expected ApiKeyValidityOutOfBoundsException, got {code}"
    assert msg == "API key can be valid for a maximum of 365 days.", f"unexpected message: {msg!r}"

    # the key's expiry (as set by the positive control) was not mutated by the rejected call
    after = {k["id"]: k for k in appsync.list_api_keys(apiId=api["apiId"])["apiKeys"]}
    assert after[key_id]["expires"] == control_expires, (
        f"a rejected UpdateApiKey changed the stored expiry from {control_expires} to "
        f"{after[key_id]['expires']}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_graphql_api(ctx, appsync, auth_type: str = "API_KEY") -> dict:
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType=auth_type,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
