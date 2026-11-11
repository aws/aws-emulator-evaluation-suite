"""api-key-update-and-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-key-update-and-list"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey patches enabled/name and the change is reflected in the GetApiKeys listing;
    once the key is deleted, that same read and a further mutation both -> NotFoundException."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-apikey-")

    created = apigw.create_api_key(name=name, enabled=True, description="initial description")
    key_id = created["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_api_key(apiKey=key_id)))
    assert created["enabled"] is True, f"expected freshly created key enabled, got {created['enabled']!r}"
    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"

    new_name = f"{name}-updated"
    updated = apigw.update_api_key(
        apiKey=key_id,
        patchOperations=[
            {"op": "replace", "path": "/enabled", "value": "false"},
            {"op": "replace", "path": "/name", "value": new_name},
            {"op": "replace", "path": "/description", "value": "updated description"},
        ],
    )
    assert updated["id"] == key_id, f"expected id {key_id!r}, got {updated['id']!r}"
    assert updated["enabled"] is False, f"expected enabled False, got {updated['enabled']!r}"
    assert updated["name"] == new_name, f"expected name {new_name!r}, got {updated['name']!r}"
    assert updated["description"] == "updated description", (
        f"expected description 'updated description', got {updated['description']!r}"
    )

    listed = apigw.get_api_keys(limit=500)["items"]
    match = next((k for k in listed if k["id"] == key_id), None)
    assert match is not None, "the updated api key must be present in the GetApiKeys listing"
    assert match["enabled"] is False, f"expected listed enabled False, got {match['enabled']!r}"
    assert match["name"] == new_name, f"expected listed name {new_name!r}, got {match['name']!r}"

    apigw.delete_api_key(apiKey=key_id)

    code, message = _error(lambda: apigw.get_api_key(apiKey=key_id))
    assert code == "NotFoundException", f"expected NotFoundException reading deleted key, got {code!r}"
    assert message == "Invalid API Key identifier specified", f"unexpected message {message!r}"

    code, message = _error(
        lambda: apigw.update_api_key(
            apiKey=key_id,
            patchOperations=[{"op": "replace", "path": "/enabled", "value": "true"}],
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException mutating deleted key, got {code!r}"
    assert message == "Invalid API Key identifier specified", f"unexpected message {message!r}"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); it must raise ClientError. Returns (Error.Code, Error.Message), never a sentinel
    for unexpected success -- an over-permissive target that lets the call through must fail the
    comparison against the expected code."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
