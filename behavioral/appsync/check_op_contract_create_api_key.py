"""op-contract-createApiKey."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-createApiKey"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey returns a da2- key with the given description, an hour-floored default 7-day expiry and a
    deletes time not before it, listed by ListApiKeys; an expiry under 1 day is refused with
    ApiKeyValidityOutOfBoundsException and an unknown apiId with NotFoundException, each with its exact message."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    t0 = int(time.time())
    resp = appsync.create_api_key(apiId=api_id, description="sim2real behavioral key")
    t1 = int(time.time())
    key = resp["apiKey"]
    ctx.on_cleanup(lambda: appsync.delete_api_key(apiId=api_id, id=key["id"]))

    assert key["id"].startswith("da2-"), f"unexpected api key id shape: {key['id']}"
    assert key["description"] == "sim2real behavioral key", (
        f"unexpected api key description: {key['description']!r}"
    )
    # AppSync floors expires/deletes to the nearest hour boundary (docs: "rounded down to
    # the nearest hour"). The default expiry is 7 days from the server's own clock, which we
    # bound by [t0, t1] around the call, so the only admissible values are the hour-floor of
    # that window's endpoints.
    admissible_expires = {
        (t + 7 * 24 * 3600) - (t + 7 * 24 * 3600) % 3600 for t in (t0, t1)
    }
    assert key["expires"] in admissible_expires, (
        f"expires={key['expires']} not an hour-floored default 7-day expiry from "
        f"[{t0}, {t1}]; expected one of {sorted(admissible_expires)}"
    )
    assert "deletes" in key and key["deletes"] is not None, "apiKey.deletes missing from da2 key"
    assert key["deletes"] >= key["expires"] - 10, "deletes timestamp must not precede expires"

    # Confirm it is discoverable via ListApiKeys
    listed = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert any(k["id"] == key["id"] for k in listed), (
        f"created key {key['id']} not found in ListApiKeys: {[k['id'] for k in listed]}"
    )

    # Error boundary: expires too close (< 1 day out) -> ApiKeyValidityOutOfBoundsException
    code, msg = _error(
        lambda: appsync.create_api_key(apiId=api_id, expires=int(time.time()) + 60)
    )
    assert code == "ApiKeyValidityOutOfBoundsException", f"unexpected error code: {code}"
    assert msg == "API key must be valid for a minimum of 1 days.", f"unexpected message: {msg!r}"

    # Error boundary: a well-formed apiId that names no API -> NotFoundException
    code, msg = _error(lambda: appsync.create_api_key(apiId="z" * 26))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "API not found.", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
