"""create-api-key-validity-out-of-bounds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "create-api-key-validity-out-of-bounds"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiKey with expires < 1 day out must fail ApiKeyValidityOutOfBoundsException,
    the rejection must not create a key, and a well-formed request (30 days out) on the same
    API still succeeds — proving the rejection is about the value, not a blanket denial."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    too_soon = int(time.time()) + 3600  # 1 hour out, below the 1-day minimum

    code, message = _error(lambda: svc.create_api_key(apiId=api_id, expires=too_soon))
    assert code == "ApiKeyValidityOutOfBoundsException", f"expected ApiKeyValidityOutOfBoundsException, got {code}"
    assert message == "API key must be valid for a minimum of 1 days.", (
        f"expected the exact minimum-validity message, got {message!r}"
    )

    keys_after_rejection = svc.list_api_keys(apiId=api_id)["apiKeys"]
    assert keys_after_rejection == [], f"rejected CreateApiKey must not create a key: {keys_after_rejection}"

    in_bounds = int(time.time()) + 30 * 24 * 3600
    created = svc.create_api_key(apiId=api_id, expires=in_bounds)["apiKey"]
    ctx.on_cleanup(lambda _a=api_id, _k=created["id"]: svc.delete_api_key(apiId=_a, id=_k))

    keys_after_control = svc.list_api_keys(apiId=api_id)["apiKeys"]
    assert [k["id"] for k in keys_after_control] == [created["id"]], (
        f"expected only the in-bounds key to exist, got {keys_after_control}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
