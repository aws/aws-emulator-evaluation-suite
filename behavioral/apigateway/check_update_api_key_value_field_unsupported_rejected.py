"""update-api-key-value-field-unsupported-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-api-key-value-field-unsupported-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey rejects patching the immutable key value; a supported patch on /name still succeeds."""
    apigw = ctx.client("apigateway")

    key_name = ctx.unique_name("sim2real-bh-key-")
    created = apigw.create_api_key(name=key_name, enabled=True)
    key_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))
    original_value = created["value"]

    # Positive control: /name is a supported patch path.
    control = apigw.update_api_key(
        apiKey=key_id,
        patchOperations=[{"op": "replace", "path": "/name", "value": key_name + "-renamed"}],
    )
    assert control["name"] == key_name + "-renamed", (
        f"expected the positive control to rename the key, got {control['name']!r}"
    )

    # Negative: /value is not a supported patch path for UpdateApiKey.
    err = _client_error(
        lambda: apigw.update_api_key(
            apiKey=key_id,
            patchOperations=[{"op": "replace", "path": "/value", "value": "sim2realBogusApiKeyValue1234567890"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    expected_message = (
        "Invalid patch path  '/value' specified for op 'replace'. "
        "Must be one of: [/description, /enabled, /name, /customerId]"
    )
    assert err.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {err.get('Message')!r}"
    )

    fetched = apigw.get_api_key(apiKey=key_id, includeValue=True)
    assert fetched["value"] == original_value, "rejected patch must not have mutated the key value"
    assert fetched["name"] == key_name + "-renamed", "the prior valid rename must remain intact"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
