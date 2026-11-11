"""update-api-key-invalid-patch-bad-request."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-api-key-invalid-patch-bad-request"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateApiKey with an unsupported JSON-Patch op path returns BadRequestException, and
    the key remains unchanged and deletable afterward."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-key-")
    created = apigw.create_api_key(
        name=name,
        enabled=True,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    key_id = created["id"]

    def _cleanup():
        try:
            apigw.delete_api_key(apiKey=key_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Positive control: a supported patch path succeeds first, so the later rejection is
    # provably specific to the unsupported path rather than every UpdateApiKey call failing.
    control_description = "sim2real-control-desc"
    control = apigw.update_api_key(
        apiKey=key_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": control_description}],
    )
    assert control["description"] == control_description, (
        f"expected the supported /description patch to apply, got {control['description']!r}"
    )

    err = _client_error(
        lambda: apigw.update_api_key(
            apiKey=key_id,
            patchOperations=[{"op": "replace", "path": "/thisFieldDoesNotExist", "value": "x"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    expected_message = (
        "Invalid patch path  '/thisFieldDoesNotExist' specified for op 'replace'. "
        "Must be one of: [/description, /enabled, /name, /customerId]"
    )
    assert err.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {err.get('Message')!r}"
    )

    # unchanged: the rejected patch neither mutated the key nor rolled back the prior valid one
    got = apigw.get_api_key(apiKey=key_id)
    assert got["name"] == name, f"expected name {name!r} unchanged, got {got['name']!r}"
    assert got["enabled"] is True, f"expected enabled=True unchanged, got {got['enabled']!r}"
    assert got["description"] == control_description, (
        f"expected the prior valid /description patch to remain intact, got {got['description']!r}"
    )

    # still deletable (no lingering server-side inconsistency from the rejected patch)
    apigw.delete_api_key(apiKey=key_id)
    err = _client_error(lambda: apigw.get_api_key(apiKey=key_id))
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException after delete, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid API Key identifier specified", (
        f"expected the exact deleted-key message, got {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
