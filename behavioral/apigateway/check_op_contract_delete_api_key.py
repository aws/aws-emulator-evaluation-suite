"""op-contract-deleteApiKey."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deleteApiKey"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApiKey removes the key so it can no longer be fetched; deleting a key id that does not
    exist is rejected with NotFoundException."""
    apigw = ctx.client("apigateway")

    name = ctx.unique_name("sim2real-behav-key-")
    created = apigw.create_api_key(name=name, enabled=True, tags={"sim2real": "op-contract-delete-api-key"})
    key_id = created["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api_key(apiKey=key_id)))

    fetched = apigw.get_api_key(apiKey=key_id)
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"
    assert fetched["enabled"] is True, f"expected enabled=True, got {fetched['enabled']!r}"

    apigw.delete_api_key(apiKey=key_id)

    err = _client_error(lambda: apigw.get_api_key(apiKey=key_id))
    assert err.get("Code") == "NotFoundException", f"key still fetchable after delete, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid API Key identifier specified", (
        f"expected the exact NotFound message from GetApiKey, got {err.get('Message')!r}"
    )

    err = _client_error(lambda: apigw.delete_api_key(apiKey="zzzznotarealapikey"))
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid API Key identifier specified", (
        f"expected the exact NotFound message from DeleteApiKey, got {err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
