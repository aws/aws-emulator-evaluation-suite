"""op-contract-deleteApiKey."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deleteApiKey"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApiKey: success removes the key from ListApiKeys + NotFoundException on double delete."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    key = appsync.create_api_key(apiId=api_id, description="sim2real delete-key test")["apiKey"]
    key_id = key["id"]

    before = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert any(k["id"] == key_id for k in before), f"created key {key_id} missing from ListApiKeys"

    resp = appsync.delete_api_key(apiId=api_id, id=key_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 from DeleteApiKey, got {status}"

    after = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    assert not any(k["id"] == key_id for k in after), "deleted api key still listed"

    # Error boundary: deleting the same (now nonexistent) key id -> NotFoundException.
    code, msg = _error(lambda: appsync.delete_api_key(apiId=api_id, id=key_id))
    assert code == "NotFoundException", f"unexpected error code: {code}"
    assert msg == f"API key not found: {key_id}", f"unexpected message: {msg!r}"


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
